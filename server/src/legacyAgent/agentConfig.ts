import { createHash } from 'node:crypto';
import type { Knex } from 'knex';
import { REMOTE_LIMITS, type LegacyAgentRemoteConfig } from '@obligarth/shared';
import { logger } from '../utils/logger';
import { vault } from '../vault';
import { instanceSettings } from './config';
import { legacyAgentRemote } from './remoteBridge';

// =============================================================================
// The configuration an agent receives (docs: agent-pont-android §4.4, §4.5,
// §6): instance settings (inventory period, minimal version), keep-alive
// service, the remote assistance (P0-15 §4.3, agents 1.1.0 and later: its
// rule, the permanent wait, the armed window), and the tenant's Knox licence key, sealed in the vault
// (tenant_secrets, purpose legacy_agent_knox_license) and referenced by
// legacy_agent_settings.knox_license ({"$secret": "<id>"}: a reference holder
// of the vault, so the row is never collected). Its version is derived from
// its content (the agent compares it, configVersion): a change of any value
// gives a new version, delivered at the next interrogation.
// =============================================================================

export const KNOX_PURPOSE = 'legacy_agent_knox_license';

export interface AgentConfig {
  version: number;
  inventorySeconds: number;
  keepAlive: boolean;
  knoxLicenseKey: string | null;
  minAgentVersionCode: number;
  /** The remote assistance (P0-15 §4.3), to an agent of REMOTE_LIMITS.minAgentVersionCode at least only. */
  remote?: LegacyAgentRemoteConfig;
}

const knoxCache = new Map<number, { at: number; id: string | null; value: string | null }>();

/** The id of the tenant's Knox key secret, or null. */
export async function knoxSecretIdOf(q: Knex | Knex.Transaction, tenantId: number): Promise<string | null> {
  const row = await q('legacy_agent_settings').where({ tenant_id: tenantId }).first('knox_license') as { knox_license: unknown } | undefined;
  const ref = (typeof row?.knox_license === 'string' ? JSON.parse(row.knox_license) : row?.knox_license) as { $secret?: unknown } | null | undefined;
  return typeof ref?.$secret === 'string' ? ref.$secret : null;
}

/** The Knox licence key of the tenant, in the tenant's transaction (cached 60 s per secret id). */
async function knoxKeyOf(trx: Knex.Transaction, tenantId: number): Promise<string | null> {
  const id = await knoxSecretIdOf(trx, tenantId);
  const hit = knoxCache.get(tenantId);
  if (hit && hit.id === id && Date.now() - hit.at < 60_000) return hit.value;
  let value: string | null = null;
  if (id) {
    try {
      const buf = await vault.readTenantSecret(tenantId, id, { trx });
      value = buf.toString('utf8');
      buf.fill(0);
    } catch (err) {
      logger.error({ tenantId, code: (err as { code?: unknown })?.code }, 'legacy agent: the Knox licence key of the tenant cannot be opened');
      value = null;
    }
  }
  knoxCache.set(tenantId, { at: Date.now(), id, value });
  return value;
}

export function forgetKnoxKey(tenantId: number): void {
  knoxCache.delete(tenantId);
}

/**
 * The configuration of the agent of a device. `agent`: the device and the versionCode the request announces; an agent
 * of REMOTE_LIMITS.minAgentVersionCode at least gets the remote object (P0-15 §4.3: enabled, waitChannel, armedUntil,
 * minAgentVersion), an older one the configuration of before (unchanged, so is its version). The version follows the
 * content, so an agent updated from 1.0.x to 1.1.0 that still announces the version it read before gets the whole
 * configuration again (finding of the agent's workflow T7: a 1.0.x ignored config.remote).
 */
export async function agentConfigFor(trx: Knex.Transaction, tenantId: number, agent?: { deviceId: number; versionCode: number }): Promise<AgentConfig> {
  const s = await instanceSettings();
  const bridge = legacyAgentRemote();
  const remote = bridge && agent && agent.versionCode >= REMOTE_LIMITS.minAgentVersionCode ? await bridge.config(trx, tenantId, agent.deviceId) : null;
  const content = {
    inventorySeconds: s.inventorySeconds, keepAlive: true, knoxLicenseKey: await knoxKeyOf(trx, tenantId), minAgentVersionCode: s.minVersionCode,
    ...(remote ? { remote } : {}),
  };
  const digest = createHash('sha256').update(JSON.stringify(content)).digest();
  // A positive 31-bit integer, never 0 (an agent without configuration announces 0 or null).
  const version = (digest.readUInt32BE(0) & 0x7fffffff) || 1;
  return { version, ...content };
}
