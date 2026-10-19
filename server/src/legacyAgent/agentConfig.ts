import { createHash } from 'node:crypto';
import type { Knex } from 'knex';
import { logger } from '../utils/logger';
import { vault } from '../vault';
import { instanceSettings } from './config';

// =============================================================================
// The configuration an agent receives (docs: agent-pont-android §4.4, §4.5,
// §6): instance settings (inventory period, minimal version), keep-alive
// service, and the tenant's Knox licence key, sealed in the vault
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

export async function agentConfigFor(trx: Knex.Transaction, tenantId: number): Promise<AgentConfig> {
  const s = await instanceSettings();
  const content = {
    inventorySeconds: s.inventorySeconds, keepAlive: true, knoxLicenseKey: await knoxKeyOf(trx, tenantId), minAgentVersionCode: s.minVersionCode,
  };
  const digest = createHash('sha256').update(JSON.stringify(content)).digest();
  // A positive 31-bit integer, never 0 (an agent without configuration announces 0 or null).
  const version = (digest.readUInt32BE(0) & 0x7fffffff) || 1;
  return { version, ...content };
}
