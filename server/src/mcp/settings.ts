import type { McpTenantIpPolicy } from '@obligarth/shared';
import { db } from '../db';
import { asIdentity, type DbActor } from '../db/context';
import { pgTextArray } from './ipUtil';

// =============================================================================
// Settings of the MCP server (docs: specs mcp-server §2.5): the singleton of
// the instance and the per-tenant override of "force an IP allow-list", read
// in the identity context (actor i:mcp), cached a few seconds; a change
// through the admin routes drops the cache at once.
// =============================================================================

export const MCP_ACTOR: DbActor = { type: 'integration', name: 'mcp' };

export interface McpSettings {
  forceIpAllowList: boolean;
  minPrefixV4: number;
  minPrefixV6: number;
  failureThreshold: number;
  failureWindowSeconds: number;
  blockSeconds: number;
  knownIpDays: number;
  maxNewBlocksPerMinute: number;
  prefixBlockThreshold: number;
  keyRequestsPerMinute: number;
  authorizationMinutes: number;
  maxPendingPerKey: number;
  maxPendingPerUser: number;
  maxCreatedPerKeyHour: number;
  obliguardEnabled: boolean;
  obliguardUrl: string | null;
  neverBlock: string[];
}

/** The defaults of the migration: what the server uses when the row cannot be read (fail safe, never wider). */
export const DEFAULT_MCP_SETTINGS: McpSettings = Object.freeze({
  forceIpAllowList: false, minPrefixV4: 16, minPrefixV6: 48, failureThreshold: 10, failureWindowSeconds: 900,
  blockSeconds: 86_400, knownIpDays: 30, maxNewBlocksPerMinute: 30, prefixBlockThreshold: 4, keyRequestsPerMinute: 600,
  authorizationMinutes: 10, maxPendingPerKey: 5, maxPendingPerUser: 20, maxCreatedPerKeyHour: 10,
  obliguardEnabled: false, obliguardUrl: null, neverBlock: [],
}) as McpSettings;

const TTL_MS = 10_000;
let cached: { at: number; settings: McpSettings; policies: Map<number, McpTenantIpPolicy> } | null = null;

export function forgetMcpSettings(): void {
  cached = null;
}

function rowToSettings(r: Record<string, any>): McpSettings {
  return {
    forceIpAllowList: r.force_ip_allowlist === true,
    minPrefixV4: Number(r.min_prefix_v4), minPrefixV6: Number(r.min_prefix_v6),
    failureThreshold: Number(r.failure_threshold), failureWindowSeconds: Number(r.failure_window_s),
    blockSeconds: Number(r.block_seconds), knownIpDays: Number(r.known_ip_days),
    maxNewBlocksPerMinute: Number(r.max_new_blocks_per_min), prefixBlockThreshold: Number(r.prefix_block_threshold),
    keyRequestsPerMinute: Number(r.key_rpm), authorizationMinutes: Number(r.authorization_minutes),
    maxPendingPerKey: Number(r.max_pending_per_key), maxPendingPerUser: Number(r.max_pending_per_user),
    maxCreatedPerKeyHour: Number(r.max_created_per_key_hour),
    obliguardEnabled: r.obliguard_enabled === true, obliguardUrl: r.obliguard_url ?? null,
    neverBlock: pgTextArray(r.never_block),
  };
}

async function load(): Promise<NonNullable<typeof cached>> {
  return asIdentity(MCP_ACTOR, async () => {
    const row = await db('mcp_settings').where({ id: 1 })
      .first('*', db.raw('never_block::text[] AS never_block')) as Record<string, any> | undefined;
    const rows = await db('mcp_tenant_policies').select('tenant_id', 'force_ip_allowlist') as Array<{ tenant_id: number; force_ip_allowlist: McpTenantIpPolicy }>;
    return {
      at: Date.now(),
      settings: row ? rowToSettings(row) : { ...DEFAULT_MCP_SETTINGS },
      policies: new Map(rows.map((r) => [Number(r.tenant_id), r.force_ip_allowlist])),
    };
  });
}

export async function mcpSettings(fresh = false): Promise<McpSettings> {
  if (!fresh && cached && Date.now() - cached.at < TTL_MS) return cached.settings;
  cached = await load();
  return cached.settings;
}

export async function tenantIpPolicies(fresh = false): Promise<Map<number, McpTenantIpPolicy>> {
  if (!fresh && cached && Date.now() - cached.at < TTL_MS) return cached.policies;
  cached = await load();
  return cached.policies;
}

/** Does tenant T force an IP allow-list on the keys reaching it (the instance setting, overridden per tenant)? */
export function tenantForcesIp(tenantId: number, settings: McpSettings, policies: Map<number, McpTenantIpPolicy>): boolean {
  const p = policies.get(Number(tenantId)) ?? 'inherit';
  if (p === 'force') return true;
  if (p === 'exempt') return false;
  return settings.forceIpAllowList;
}
