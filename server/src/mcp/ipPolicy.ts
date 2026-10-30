import { MASTER_TENANT_ID, type McpIpMode } from '@obligarth/shared';
import { db } from '../db';
import { asIdentity, asTenant } from '../db/context';
import { announce, registerPlatformOnlyAlertKinds } from '../services/liveAlert.service';
import { logger } from '../utils/logger';
import { appendQuiet, systemCtx } from './audit';
import type { McpKeyInfo } from './caller';
import { compileCidrs, pgTextArray } from './ipUtil';
import { effectiveTenants, targetsOf } from './perimeter';
import { MCP_ACTOR, mcpSettings } from './settings';

// =============================================================================
// The IP policy of the MCP server (owner decision 3; docs: specs mcp-server
// §3.6), as a cached snapshot, never computed per request:
//   closed  no active key: every request answers 401 and counts as a failure
//           (no instant ban on a vacuous "every key has an IP");
//   strict  at least one active key and none open: the union of the IPs of the
//           active keys is the global list; an address outside it and outside
//           the known list is blocked at once, for good, and reported;
//   rate    at least one open key (no IP list, and at least one tenant of its
//           effective perimeter does not force an allow-list): failures are
//           counted per address, blocked beyond the threshold.
// Known list (strict only): the IPs of keys revoked or expired within
// known_ip_days, and of active keys whose owner became inactive: such an
// address goes to the rate path, never to the instant ban.
// Recomputed when a key is created, revoked or narrowed, the settings or a
// tenant policy change, and every minute (expiries, lost rights); a change of
// mode is audited and raised as a platform alert.
// =============================================================================

export interface PolicySnapshot {
  mode: McpIpMode;
  globalList: string[];
  knownList: string[];
  activeKeys: number;
  openKeys: number;
  at: number;
  inGlobal: (ip: string) => boolean;
  inKnown: (ip: string) => boolean;
}

const MODE_ALERT_KIND = 'mcp.ip_mode_changed';
registerPlatformOnlyAlertKinds([MODE_ALERT_KIND]);

let snapshot: PolicySnapshot | null = null;
let computing: Promise<PolicySnapshot> | null = null;
let dirty = false;

/** The current snapshot (null until the first computation: the gate then never bans, it only counts). */
export function currentPolicy(): PolicySnapshot | null {
  return snapshot;
}

async function compute(): Promise<PolicySnapshot> {
  const s = await mcpSettings(true);
  const rows = await asIdentity(MCP_ACTOR, () => db('access_keys as k').join('users as u', 'u.id', 'k.user_id')
    .where((w) => w.whereNull('k.revoked_at').orWhere('k.revoked_at', '>', new Date(Date.now() - s.knownIpDays * 86_400_000)))
    .select('k.id', 'k.user_id', 'k.scopes', 'k.tenant_mode', 'k.group_mode', 'k.device_mode', db.raw('k.ip_allow::text[] AS ip_allow'),
      'k.expires_at', 'k.revoked_at', 'k.credential_version', 'k.public_id', 'k.name',
      'u.is_active', 'u.role', db.raw('u.credential_version AS user_cv'))) as Array<Record<string, any>>;
  const ids = rows.map((r) => String(r.id));
  const targetRows = ids.length === 0 ? [] : await asIdentity(MCP_ACTOR, () => db('access_key_targets').whereIn('key_id', ids)
    .select('key_id', 'kind', 'tenant_id', 'ref_id')) as Array<{ key_id: string; kind: string; tenant_id: number; ref_id: number | null }>;
  const byKey = new Map<string, typeof targetRows>();
  for (const t of targetRows) { const k = String(t.key_id); if (!byKey.has(k)) byKey.set(k, []); byKey.get(k)!.push(t); }

  const now = Date.now();
  const global = new Set<string>();
  const known = new Set<string>();
  let active = 0;
  let open = 0;
  for (const r of rows) {
    const ips = pgTextArray(r.ip_allow);
    const alive = r.revoked_at === null && new Date(r.expires_at).getTime() > now;
    const recent = r.revoked_at !== null || new Date(r.expires_at).getTime() > now - s.knownIpDays * 86_400_000;
    if (!alive) { if (recent) ips.forEach((ip) => known.add(ip)); continue; }
    if (r.is_active !== true || Number(r.user_cv) !== Number(r.credential_version)) { ips.forEach((ip) => known.add(ip)); continue; }
    active++;
    ips.forEach((ip) => global.add(ip));
    if (ips.length === 0) {
      const key: Pick<McpKeyInfo, 'tenantMode' | 'ipAllow'> = { tenantMode: r.tenant_mode, ipAllow: [] };
      try {
        const eff = await effectiveTenants({
          userId: Number(r.user_id), isPlatformAdmin: r.role === 'admin', key, targets: targetsOf(byKey.get(String(r.id)) ?? []),
        });
        // A key without IPs whose tenants all force an allow-list, or that lost every tenant, cannot be used: not open.
        if (eff.tenants.length > 0) open++;
      } catch (err) {
        // Unknown: counted as open (never a strict ban decided on a partial view).
        open++;
        logger.warn({ err, keyId: r.public_id }, 'mcp: perimeter of a key not computed for the IP policy');
      }
    }
  }
  const mode: McpIpMode = active === 0 ? 'closed' : open > 0 ? 'rate' : 'strict';
  const globalList = [...global].sort();
  const knownList = [...known].filter((ip) => !global.has(ip)).sort();
  return {
    mode, globalList, knownList, activeKeys: active, openKeys: open, at: now,
    inGlobal: compileCidrs(globalList), inKnown: compileCidrs(knownList),
  };
}

async function announceModeChange(from: McpIpMode, to: PolicySnapshot): Promise<void> {
  await appendQuiet({
    tenantId: MASTER_TENANT_ID, action: 'mcp.ip.mode_changed',
    details: { from, to: to.mode, openKeys: to.openKeys, activeKeys: to.activeKeys },
  }, systemCtx());
  try {
    await asTenant(MASTER_TENANT_ID, MCP_ACTOR, async () => {
      const [row] = await db('live_alerts').insert({
        tenant_id: MASTER_TENANT_ID, severity: to.mode === 'strict' ? 'info' : 'warning',
        title: 'MCP server: IP mode changed',
        message: `The IP mode of the MCP server went from ${from} to ${to.mode} (${to.activeKeys} active key(s), ${to.openKeys} without an IP allow-list).`,
        navigate_to: '/settings', stable_key: null, kind: MODE_ALERT_KIND,
        i18n_key: 'settings.mcp.alerts.modeChanged', i18n_params: JSON.stringify({ from, to: to.mode, active: to.activeKeys, open: to.openKeys }),
      }).returning('*');
      if (row) await announce(row, MASTER_TENANT_ID);
    });
  } catch (err) {
    logger.warn({ err }, 'mcp: alert of the IP mode change not raised');
  }
}

/** Recomputes the snapshot now (deduplicated); a change of mode is audited and raised. */
export async function refreshPolicy(): Promise<PolicySnapshot> {
  if (computing) { dirty = true; return computing; }
  computing = (async () => {
    try {
      const prev = snapshot;
      const next = await compute();
      snapshot = next;
      if (prev && prev.mode !== next.mode) {
        logger.warn({ from: prev.mode, to: next.mode, activeKeys: next.activeKeys, openKeys: next.openKeys }, 'mcp: IP mode changed');
        await announceModeChange(prev.mode, next);
      }
      return next;
    } finally {
      computing = null;
      if (dirty) { dirty = false; void refreshPolicy().catch(() => undefined); }
    }
  })();
  return computing;
}

/** A key, the settings or a tenant policy changed: the snapshot is recomputed (in the background; never throws). */
export function invalidatePolicy(): void {
  void refreshPolicy().catch((err) => logger.warn({ err }, 'mcp: IP policy not recomputed'));
}
