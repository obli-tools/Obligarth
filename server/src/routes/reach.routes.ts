import fs from 'fs';
import path from 'path';
import { Router } from 'express';
import { db } from '../db';
import { scriptService } from '../services/script.service';
import { oblireachHub } from '../services/oblireachHub.service';
import { agentHub } from '../services/agentHub.service';
import { permissionService } from '../services/permission.service';
import { MASTER_TENANT_ID, isMasterTenant } from '@obliance/shared';
import { resolveOverviewScope, type ScopeDeps } from './reachOverviewScope';

/**
 * The Windows sessions an ObliReach agent reported (oblireach_devices.sessions,
 * written from its heartbeat): the list only when it is one, each entry an
 * object. A malformed or hostile report counts as none: the Desktop and the
 * web draw these rows, and one bad row must not fail the whole overview.
 */
function orSessions(raw: unknown): Record<string, unknown>[] {
  let v: unknown = raw;
  if (typeof raw === 'string') {
    try { v = JSON.parse(raw); } catch { return []; }
  }
  return Array.isArray(v)
    ? v.filter((s): s is Record<string, unknown> => s !== null && typeof s === 'object' && !Array.isArray(s))
    : [];
}

const router = Router();

/**
 * ?agents=1: what a client needs to offer the Obliance agent's tools on a
 * device (remote terminals, file explorer) — the same gates as the web's
 * device page. Hints only: every action is checked again by its own route.
 */
function agentFields(dev: any, admin: boolean, lackRemote: Set<number>, lackFiles: Set<number>) {
  const approved = dev.approval_status === 'approved';
  return {
    agent: {
      live: agentHub.isConnected(Number(dev.id)),
      flavor: dev.agent_flavor === 'legacy' ? 'legacy' as const : 'modern' as const,
      version: typeof dev.agent_version === 'string' && dev.agent_version ? dev.agent_version : null,
    },
    privacy: {
      enabled: !!dev.privacy_mode_enabled,
      passwordSet: !!dev.privacy_password_set,
    },
    can: {
      remote: approved && (admin || !lackRemote.has(Number(dev.id))),
      files: approved && (admin || !lackFiles.has(Number(dev.id))),
    },
  };
}

// ── Oblireach Desktop Client API ─────────────────────────────────────────────
// All routes require requireAuth + requireTenant (applied in index.ts).

const OR_ONLINE_THRESHOLD_MS = 2 * 60 * 1000;

// ── Version cache (shared with oblireach-agent.routes.ts logic) ──────────────
let _cachedLatestVersion: string | null = null;
let _cachedLatestVersionAt = 0;
const VERSION_TTL_MS = 60_000;

function getLatestObliReachVersion(): string | null {
  const now = Date.now();
  if (now - _cachedLatestVersionAt < VERSION_TTL_MS) return _cachedLatestVersion;
  try {
    const fp = path.resolve(__dirname, '../../../../agent/dist/oblireach-version.txt');
    _cachedLatestVersion = fs.readFileSync(fp, 'utf-8').trim() || null;
  } catch {
    _cachedLatestVersion = null;
  }
  _cachedLatestVersionAt = now;
  return _cachedLatestVersion;
}

/**
 * GET /reach/overview
 *
 * Returns all agent devices enriched with their Oblireach status, grouped by
 * device group. Used by the Oblireach desktop client device tree.
 *
 * Response:
 * {
 *   groups: Array<{
 *     id: number,          // 0 = ungrouped (master: -tenantId = that tenant's ungrouped)
 *     name: string,        // display path: "Parent / Child" (master: "Tenant / Parent / Child")
 *     groupName: string, parentId: number | null, depth: number,  // Obliance group tree
 *     tenantId: number, tenantName?: string,                       // tenantName on the master only
 *     devices: Array<{
 *       id: number,
 *       uuid: string,
 *       hostname: string,
 *       status: string,
 *       osType: string,
 *       lastLoggedInUser: string | null,  // last user seen logged in (agent-reported, trimmed; null when none)
 *       oblireach: {
 *         installed: boolean,
 *         online: boolean,
 *         sessions: ObliReachSession[],
 *       }
 *     }>
 *   }>,               // Obliance order: tenant (Default first, then by name), group tree depth-first
 *                     // (sort_order, name), Ungrouped last; only groups holding visible devices
 *   tenants?: Array<{ id: number, name: string }>,  // several tenants listed (master god view, or ?tenantId=), same order
 *   scope?: { all: true } | { all: false, tenantIds: number[] },  // only with ?tenantId= (see below)
 *   features?: { agents: true },                     // only with ?agents=1 (see below)
 * }
 *
 * ?tenantId=<id> | all (optional; the Oblireach Desktop's multi-server mode):
 * the tenants to list without switching the session's tenant. Only tenants
 * the user can already switch to (reachOverviewScope.ts: platform admins any
 * tenant, the master one or `all` = the god view; other users their own
 * tenants and the session's current one): never more than POST
 * /api/tenant/switch + GET /reach/overview gives, the team filter still
 * applies. 400 malformed, 403 no access, 404 unknown tenant (admin). The
 * answer then carries `scope` (how a client tells this server supports it);
 * without the parameter it is unchanged (the session's tenant; god view for
 * an admin on the master tenant).
 *
 * ?agents=1 (optional, opt-in; the Oblireach Desktop's remote terminals and
 * file explorer): the SAME devices (tenant scope, team visibility, group
 * order unchanged), plus the APPROVED devices that have no ObliReach (only the
 * Obliance agent: terminals and explorer go through it), and on every device:
 *   oblireach: always present; { installed: false, online: false, version: null,
 *              updateAvailable: false, sessions: [] } for a device without it,
 *   agent:   { live: boolean,          // the agent's command channel is connected
 *              flavor: 'modern' | 'legacy', version: string | null },
 *   privacy: { enabled: boolean, passwordSet: boolean },
 *   can:     { remote: boolean, files: boolean },  // capabilities 'remote' / 'files'
 *              // (admins: true; false on a device that is not approved).
 * The answer then carries features: { agents: true }. Without the parameter the
 * answer is unchanged (Desktop 1.0.11+ assume every device has ObliReach). It
 * never widens what the caller sees: the devices added are filtered exactly
 * like the others, and every action is checked again by its own route.
 */
const overviewScopeDeps: ScopeDeps = {
  async tenantExists(id) { return !!(await db('tenants').where({ id }).first('id')); },
  async userTenantIds(userId) { return (await db('user_tenants').where({ user_id: userId }).pluck('tenant_id')).map(Number); },
};

router.get('/overview', async (req, res, next) => {
  try {
    const tenantId = req.tenantId!;
    const admin = req.session.role === 'admin';
    const withAgents = req.query.agents === '1';
    const scope = await resolveOverviewScope(req.query.tenantId,
      { userId: req.session.userId!, isAdmin: admin, currentTenantId: tenantId }, overviewScopeDeps);
    // all: every tenant. Without ?tenantId=: master tenant = god view
    // for ADMINS only. A non-admin member of the master tenant
    // stays on the master tenant's own devices (the team filter below then
    // applies), like the other tenants: a team scope must never reach
    // another tenant.
    let all: boolean;
    let ids: number[];
    if (scope === null) { all = isMasterTenant(tenantId) && admin; ids = [tenantId]; }
    else if (scope.all) { all = true; ids = []; }
    else { all = false; ids = scope.tenantIds; }
    // Several tenants listed: each group says its tenant (name, path prefix).
    const multi = all || ids.length > 1;

    // Fetch all devices of the tenants listed (all of them: god view)
    const devQ = db('devices').orderBy('hostname');
    if (!all) devQ.whereIn('tenant_id', ids);
    const devices = await devQ;

    // Fetch all oblireach device records of those tenants
    const orQ = db('oblireach_devices');
    if (!all) orQ.whereIn('tenant_id', ids);
    const orRows = await orQ;

    // Build a map: device_uuid → oblireach record
    const now = Date.now();
    const latestVersion = getLatestObliReachVersion();
    const orMap = new Map<string, { online: boolean; version: string | null; sessions: any[] }>();
    for (const row of orRows) {
      orMap.set(row.device_uuid, {
        online: oblireachHub.isConnected(row.device_uuid) || (row.last_seen_at
          ? now - new Date(row.last_seen_at).getTime() < OR_ONLINE_THRESHOLD_MS
          : false),
        version: row.version || null,
        sessions: orSessions(row.sessions),
      });
    }

    // Groups in Obliance's order (sort_order, then name), of the tenants listed
    const groupQ = db('device_groups').orderBy('sort_order').orderBy('name');
    if (!all) groupQ.whereIn('tenant_id', ids);
    const groupRows = await groupQ;

    const tenantNames = new Map<number, string>();
    if (multi) {
      const tq = db('tenants').select('id', 'name');
      if (!all) tq.whereIn('id', ids);
      for (const t of await tq) tenantNames.set(t.id, t.name);
    }
    const tenantLabel = (id: number) => tenantNames.get(id) || ('Tenant #' + id);

    type OutGroup = {
      id: number; name: string; groupName: string; parentId: number | null; depth: number;
      tenantId: number; tenantName?: string; devices: any[];
    };
    const byId = new Map<number, { row: any; devices: any[]; children: number[] }>();
    for (const g of groupRows) byId.set(g.id, { row: g, devices: [], children: [] });
    const roots = new Map<number, number[]>(); // tenant → root group ids, in order
    for (const g of groupRows) {
      const parent = g.parent_id != null ? byId.get(g.parent_id) : undefined;
      if (parent && parent.row.tenant_id === g.tenant_id) parent.children.push(g.id);
      else {
        if (!roots.has(g.tenant_id)) roots.set(g.tenant_id, []);
        roots.get(g.tenant_id)!.push(g.id);
      }
    }
    const ungroupedByTenant = new Map<number, any[]>();

    // Filter devices by user permissions
    let visibleDeviceIds: number[] | 'all' = 'all';
    if (req.session.role !== 'admin') {
      visibleDeviceIds = await permissionService.getVisibleDeviceIds(req.session.userId!, false) as number[] | 'all';
    }
    const visible = visibleDeviceIds === 'all' ? null : new Set(visibleDeviceIds);
    // Only devices where the Oblireach agent has been installed; with
    // ?agents=1 also the approved devices that only have the Obliance agent.
    // Then the permission filter.
    const listed = devices.filter((dev: any) =>
      (orMap.has(dev.uuid) || (withAgents && dev.approval_status === 'approved'))
      && (visible === null || visible.has(dev.id)));

    // ?agents=1: capabilities of a non-admin on the devices listed (2 bulk
    // queries); admins hold every capability.
    let lackRemote = new Set<number>();
    let lackFiles = new Set<number>();
    if (withAgents && !admin && listed.length) {
      const ids = listed.map((dev: any) => Number(dev.id));
      lackRemote = new Set(await permissionService.devicesLackingCapability(req.session.userId!, ids, 'remote'));
      lackFiles = new Set(await permissionService.devicesLackingCapability(req.session.userId!, ids, 'files'));
    }

    for (const dev of listed) {
      const or = orMap.get(dev.uuid);

      const enriched = {
        id: dev.id,
        uuid: dev.uuid,
        tenantId: dev.tenant_id,
        hostname: dev.display_name || dev.hostname,
        status: dev.status ?? 'unknown',
        osType: dev.os_type ?? 'unknown',
        // devices.last_logged_in_user (agent push): the same value the Obliance
        // device list / detail shows for a device the caller can already see
        // (the tenant and permission filters above apply). Agent-reported,
        // untrusted text: clients render it as text, never as markup.
        lastLoggedInUser: typeof dev.last_logged_in_user === 'string' && dev.last_logged_in_user.trim()
          ? dev.last_logged_in_user.trim() : null,
        oblireach: or ? {
          installed: true,
          online: or.online,
          version: or.version,
          updateAvailable: !!(latestVersion && or.version && latestVersion !== or.version),
          sessions: or.sessions,
        } : {
          installed: false,
          online: false,
          version: null,
          updateAvailable: false,
          sessions: [],
        },
        ...(withAgents ? agentFields(dev, admin, lackRemote, lackFiles) : {}),
      };

      const g = dev.group_id ? byId.get(dev.group_id) : undefined;
      if (g) g.devices.push(enriched);
      else {
        if (!ungroupedByTenant.has(dev.tenant_id)) ungroupedByTenant.set(dev.tenant_id, []);
        ungroupedByTenant.get(dev.tenant_id)!.push(enriched);
      }
    }

    // Output like Obliance: tenants (several listed) Default first then by name;
    // inside a tenant the group tree depth-first (parent, then its sub-groups
    // in sort order); "Ungrouped" last. A group is listed when it or one of
    // its sub-groups holds a visible device. `name` is a display path
    // ("Tenant / Parent / Child" with several tenants) for clients drawing a flat
    // list; groupName / parentId / depth / tenantId / tenantName let a client
    // draw the tree (expanded or not).
    const hasDevices = (id: number): boolean => {
      const n = byId.get(id)!;
      return n.devices.length > 0 || n.children.some(hasDevices);
    };
    const result: OutGroup[] = [];
    const walk = (id: number, depth: number, path: string[]) => {
      const n = byId.get(id)!;
      if (!hasDevices(id)) return;
      const own = [...path, n.row.name];
      n.devices.sort((x, y) => x.hostname.localeCompare(y.hostname));
      result.push({
        id, name: own.join(' / '), groupName: n.row.name, parentId: depth > 0 ? n.row.parent_id : null, depth,
        tenantId: n.row.tenant_id, ...(multi ? { tenantName: tenantLabel(n.row.tenant_id) } : {}), devices: n.devices,
      });
      for (const c of n.children) walk(c, depth + 1, own);
    };
    const tenantIds = [...new Set<number>([...roots.keys(), ...ungroupedByTenant.keys()])];
    if (!multi) tenantIds.splice(0, tenantIds.length, ...ids);
    tenantIds.sort((x, y) => (x === MASTER_TENANT_ID ? -1 : y === MASTER_TENANT_ID ? 1 : tenantLabel(x).localeCompare(tenantLabel(y))));
    const tenantsOut: Array<{ id: number; name: string }> = [];
    for (const t of tenantIds) {
      const before = result.length;
      const prefix = multi ? [tenantLabel(t)] : [];
      for (const r of roots.get(t) || []) walk(r, 0, prefix);
      const loose = (ungroupedByTenant.get(t) || []).sort((x, y) => x.hostname.localeCompare(y.hostname));
      if (loose.length) {
        result.push({
          id: multi ? -t : 0, name: [...prefix, 'Ungrouped'].join(' / '), groupName: 'Ungrouped', parentId: null, depth: 0,
          tenantId: t, ...(multi ? { tenantName: tenantLabel(t) } : {}), devices: loose,
        });
      }
      if (multi && result.length > before) tenantsOut.push({ id: t, name: tenantLabel(t) });
    }

    res.json({ data: { groups: result, ...(multi ? { tenants: tenantsOut } : {}),
      ...(scope !== null ? { scope: all ? { all: true } : { all: false, tenantIds: ids } } : {}),
      ...(withAgents ? { features: { agents: true } } : {}) } });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /reach/scripts
 *
 * Returns all scripts marked as available_in_reach for the tenant.
 * Optionally filtered by platform.
 */
router.get('/scripts', async (req, res, next) => {
  try {
    const { platform } = req.query as { platform?: string };
    const scripts = await scriptService.getScripts(req.tenantId!, {
      platform: platform || undefined,
      availableInReach: true,
    });
    res.json({ data: { scripts } });
  } catch (err) {
    next(err);
  }
});

export default router;
