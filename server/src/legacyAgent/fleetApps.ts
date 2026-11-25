import { Router } from 'express';
import {
  LEGACY_AGENT_FLEET_APPS_MIN_PEERS, LEGACY_AGENT_FLEET_APPS_MIN_SHARE, LEGACY_AGENT_PACKAGE,
  type LegacyAgentFleetAppView, type LegacyAgentFleetAppsView,
} from '@obligarth/shared';
import { db } from '../db';
import { AppError } from '../middleware/errorHandler';
import { deviceOf, visible, wrap } from './routes';

// =============================================================================
// The apps of the fleet a device lacks (a phone reset in a shop: the store's apps to put back), mounted with the bridge
// agent's routes at /api/legacy-agent (createLegacyAgentRouter):
//   GET /devices/:id/fleet-apps   the non-system apps the device's peers carry and it does not, with the package of the
//                                 tenant's store to install for each (the version most of the peers run when the store
//                                 holds it, else the store's highest confirmed one), and whether an install is already
//                                 open on the device. The console queues the chosen ones through the command route
//                                 (app.install: its capability, restriction and guard, unchanged).
// The peers: the enrolled, unrevoked bridge devices the caller sees in the device's group and its sub-groups; when they
// are fewer than LEGACY_AGENT_FLEET_APPS_MIN_PEERS, the parent group's, up to the root; a device without a group compares
// with the whole tenant. Only the apps on LEGACY_AGENT_FLEET_APPS_MIN_SHARE of the peers at least are listed. Never the
// agent itself, the leftovers of the former MDM (net.soti.*) nor the web apps Chrome builds per device.
// Reads only, in the request's database context.
// =============================================================================

const EXCLUDED = (pkg: string): boolean =>
  pkg === LEGACY_AGENT_PACKAGE || pkg.startsWith('net.soti.') || pkg.startsWith('org.chromium.webapk.');

interface Scope { groupId: number | null; groupName: string | null; peerIds: number[] }

/** The peers of a device: its group's subtree, widened to the parent while they are too few (module comment). */
async function peersOf(tenantId: number, deviceId: number, groupId: number | null, seen: number[] | 'all'): Promise<Scope> {
  const peersIn = async (ancestor: number | null): Promise<number[]> => {
    let q = db('legacy_agent_devices as a')
      .join('devices as d', function j() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
      .where('a.tenant_id', tenantId).whereNull('a.revoked_at').where('d.enrollment_state', 'enrolled').whereNot('d.id', deviceId);
    if (ancestor !== null) {
      q = q.whereIn('d.group_id', db('device_group_closure').where({ tenant_id: tenantId, ancestor_id: ancestor }).select('descendant_id'));
    }
    if (seen !== 'all') q = q.whereRaw('d.id = ANY (?::int[])', [seen]);
    return (await q.pluck('d.id') as Array<number | string>).map(Number);
  };
  if (groupId !== null) {
    const ancestors = await db('device_group_closure as c').join('device_groups as g', function j() {
      this.on('g.id', '=', 'c.ancestor_id').andOn('g.tenant_id', '=', 'c.tenant_id');
    }).where({ 'c.tenant_id': tenantId, 'c.descendant_id': groupId }).orderBy('c.depth', 'asc')
      .select('c.ancestor_id as id', 'g.name') as Array<{ id: number | string; name: string }>;
    let last: Scope | null = null;
    for (const a of ancestors) {
      last = { groupId: Number(a.id), groupName: a.name, peerIds: await peersIn(Number(a.id)) };
      if (last.peerIds.length >= LEGACY_AGENT_FLEET_APPS_MIN_PEERS) return last;
    }
    if (last && ancestors.length > 0 && last.peerIds.length > 0) {
      // The root group still has too few: the whole tenant says more (another root may hold the fleet).
      const all = await peersIn(null);
      return all.length > last.peerIds.length ? { groupId: null, groupName: null, peerIds: all } : last;
    }
  }
  return { groupId: null, groupName: null, peerIds: await peersIn(null) };
}

/** The most frequent value of a list (the highest on a tie), null when empty. */
function mostCommon(values: string[]): string | null {
  const n = new Map<string, number>();
  for (const v of values) n.set(v, (n.get(v) ?? 0) + 1);
  let best: string | null = null;
  let bestN = 0;
  for (const [v, c] of n) {
    if (c > bestN || (c === bestN && best !== null && Number(v) > Number(best))) { best = v; bestN = c; }
  }
  return best;
}

export async function deviceFleetApps(tenantId: number, deviceId: number, seen: number[] | 'all'): Promise<LegacyAgentFleetAppsView> {
  const dev = await db('devices').where({ tenant_id: tenantId, id: deviceId }).first('group_id') as { group_id: number | null } | undefined;
  if (!dev) throw new AppError(404, 'Device not found');
  const scope = await peersOf(tenantId, deviceId, dev.group_id === null ? null : Number(dev.group_id), seen);
  const peers = scope.peerIds.length;
  const view: LegacyAgentFleetAppsView = {
    deviceId, evaluatedAt: new Date().toISOString(), scope: { groupId: scope.groupId, groupName: scope.groupName, peers }, items: [],
  };
  if (peers === 0) return view;

  // The device's own apps, system ones included (an app it carries in any form is not missing).
  const own = new Set(await db('device_apps').where({ tenant_id: tenantId, device_id: deviceId, source: 'agent_report' }).pluck('identifier') as string[]);
  const rows = await db('device_apps').where({ tenant_id: tenantId, source: 'agent_report', is_system: false })
    .whereRaw('device_id = ANY (?::int[])', [scope.peerIds])
    .select('device_id', 'identifier', 'name', 'version', 'short_version') as Array<{ device_id: number; identifier: string; name: string | null; version: string | null; short_version: string | null }>;
  const byApp = new Map<string, { devices: Set<number>; labels: string[]; codes: string[]; names: Map<string, string | null> }>();
  for (const r of rows) {
    if (own.has(r.identifier) || EXCLUDED(r.identifier)) continue;
    let e = byApp.get(r.identifier);
    if (!e) { e = { devices: new Set(), labels: [], codes: [], names: new Map() }; byApp.set(r.identifier, e); }
    e.devices.add(Number(r.device_id));
    if (r.name) e.labels.push(r.name);
    if (r.short_version) { e.codes.push(r.short_version); if (!e.names.has(r.short_version)) e.names.set(r.short_version, r.version); }
  }
  const listed = [...byApp.entries()].filter(([, e]) => e.devices.size / peers >= LEGACY_AGENT_FLEET_APPS_MIN_SHARE);
  if (listed.length === 0) return view;

  const names = listed.map(([p]) => p);
  const packages = await db('legacy_agent_packages').where({ tenant_id: tenantId }).whereIn('package_name', names).whereNotNull('confirmed_at')
    .select('id', 'package_name', 'version_code', 'version_name', 'label', 'size_bytes') as Array<Record<string, any>>;
  const open = new Set((await db('legacy_agent_commands').where({ tenant_id: tenantId, device_id: deviceId, request_type: 'app.install' })
    .whereIn('state', ['pending', 'sent']).select(db.raw("params->>'packageName' AS p")) as Array<{ p: string | null }>).map((r) => r.p));

  view.items = listed.map(([packageName, e]): LegacyAgentFleetAppView => {
    const common = mostCommon(e.codes);
    const mine = packages.filter((p) => p.package_name === packageName);
    const pick = mine.find((p) => common !== null && String(p.version_code) === common)
      ?? [...mine].sort((a, b) => Number(b.version_code) - Number(a.version_code))[0] ?? null;
    return {
      packageName, label: mostCommon(e.labels), peersWith: e.devices.size, share: e.devices.size / peers,
      commonVersion: common === null ? null : { versionCode: common, versionName: e.names.get(common) ?? null },
      package: pick ? {
        id: String(pick.id).toLowerCase(), versionCode: String(pick.version_code), versionName: pick.version_name ?? null,
        label: pick.label ?? null, sizeBytes: Number(pick.size_bytes),
      } : null,
      queued: open.has(packageName),
    };
  }).sort((a, b) => b.share - a.share || a.packageName.localeCompare(b.packageName));
  return view;
}

export function fleetAppsRouter(): Router {
  const router = Router();
  router.get('/devices/:id/fleet-apps', wrap(async (req, res) => {
    const id = await deviceOf(req);
    const tenantId = req.tenantId!;
    const sat = await db('legacy_agent_devices').where({ tenant_id: tenantId, device_id: id }).first('device_id');
    if (!sat) throw new AppError(404, 'Device not found');
    res.json({ success: true, data: await deviceFleetApps(tenantId, id, await visible(req)) });
  }));
  return router;
}
