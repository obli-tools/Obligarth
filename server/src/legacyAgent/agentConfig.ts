import { createHash } from 'node:crypto';
import type { Knex } from 'knex';
import { LEGACY_AGENT_POLICY_MIN_VERSION_CODE, REMOTE_LIMITS, type JsonValue, type LegacyAgentRemoteConfig } from '@obligarth/shared';
import { audit } from '../audit';
import { tenantFrozen } from '../guard/frozen';
import { isCompileError } from '../mdm/policies/artifacts';
import { logger } from '../utils/logger';
import { vault } from '../vault';
import { LEGACY_AGENT_ACTOR } from './actor';
import { instanceSettings } from './config';
import { frozenWithhold, policyArtifactRow, renderAgentPolicy } from './policyDelivery';
import { legacyAgentRemote } from './remoteBridge';

// =============================================================================
// The configuration an agent receives (docs: agent-pont-android §4.4, §4.5,
// §6): instance settings (inventory period, minimal version), keep-alive
// service, the remote assistance (P0-15 §4.3, agents 1.1.0 and later: its
// rule, the permanent wait, the armed window), the tenant's Knox licence key,
// sealed in the vault (tenant_secrets, purpose legacy_agent_knox_license) and
// referenced by legacy_agent_settings.knox_license ({"$secret": "<id>"}: a
// reference holder of the vault, so the row is never collected), and, to an
// agent 1.3.0 or later, its policy (lot PONT-POL §8.1: the rendered artifact
// agent:policy, or null when none is desired).
// Its version is derived from what it is made of, cheaply on every poll: the
// settings, the id of the Knox secret (never the key), the remote object, the
// desired hash of the policy and the freeze. The agent compares it
// (configVersion): the same version answers no configuration and reads no
// secret; another one builds the whole configuration. A vault failure while
// building it (the Knox key, a Wi-Fi secret, the kiosk PIN) gives a degraded
// version (bit 30 flipped), which the agent announces at its next poll: the
// whole configuration is built again until it succeeds. On such a failure the
// Knox key is left out (an agent keeps its key when the key is absent), never
// sent as null.
// =============================================================================

export const KNOX_PURPOSE = 'legacy_agent_knox_license';

export interface AgentConfig {
  version: number;
  inventorySeconds: number;
  keepAlive: boolean;
  /** Absent: the agent keeps its key (a vault failure). */
  knoxLicenseKey?: string | null;
  minAgentVersionCode: number;
  /** The remote assistance (P0-15 §4.3), to an agent of REMOTE_LIMITS.minAgentVersionCode at least only. */
  remote?: LegacyAgentRemoteConfig;
  /** The agent policy (lot PONT-POL), to an agent of 1.3.0 at least only: null when none is desired. */
  policy?: Record<string, JsonValue> | null;
}

export interface AgentConfigAnswer {
  version: number;
  /** null: the agent already holds this version. */
  config: AgentConfig | null;
  /** A secret could not be read (the Knox key or one of the policy): the version is the degraded one, rebuilt at the
   *  next poll. */
  degraded: boolean;
  /** A secret of the policy itself could not be read: the policy is not marked delivered (deliver:vault_unavailable).
   *  The Knox key alone never touches the policy's state. */
  policyDegraded: boolean;
  /** The hash of the policy the configuration carries in full (to mark delivered), or null. */
  deliveredPolicyHash: string | null;
}

const knoxCache = new Map<number, { at: number; id: string | null; value: string | null; failed: boolean }>();

/** The id of the tenant's Knox key secret, or null. */
export async function knoxSecretIdOf(q: Knex | Knex.Transaction, tenantId: number): Promise<string | null> {
  const row = await q('legacy_agent_settings').where({ tenant_id: tenantId }).first('knox_license') as { knox_license: unknown } | undefined;
  const ref = (typeof row?.knox_license === 'string' ? JSON.parse(row.knox_license) : row?.knox_license) as { $secret?: unknown } | null | undefined;
  return typeof ref?.$secret === 'string' ? ref.$secret : null;
}

/** The Knox licence key of the tenant, in the tenant's transaction (cached 60 s per secret id, a failure too). */
async function knoxKeyOf(trx: Knex.Transaction, tenantId: number, id: string | null): Promise<{ value: string | null; failed: boolean }> {
  const hit = knoxCache.get(tenantId);
  if (hit && hit.id === id && Date.now() - hit.at < 60_000) return { value: hit.value, failed: hit.failed };
  let value: string | null = null;
  let failed = false;
  if (id) {
    try {
      const buf = await vault.readTenantSecret(tenantId, id, { trx });
      value = buf.toString('utf8');
      buf.fill(0);
    } catch (err) {
      logger.error({ tenantId, code: (err as { code?: unknown })?.code }, 'legacy agent: the Knox licence key of the tenant cannot be opened');
      value = null;
      failed = true;
    }
  }
  knoxCache.set(tenantId, { at: Date.now(), id, value, failed });
  return { value, failed };
}

export function forgetKnoxKey(tenantId: number): void {
  knoxCache.delete(tenantId);
}

/** A positive 31-bit integer, never 0 (an agent without configuration announces 0 or null). */
function versionOf(input: unknown): number {
  const digest = createHash('sha256').update(JSON.stringify(input)).digest();
  return (digest.readUInt32BE(0) & 0x7fffffff) || 1;
}

/** The version of a degraded answer: never the computed one (bit 30 flipped), never 0. */
export const degradedVersion = (v: number): number => ((v ^ 0x40000000) & 0x7fffffff) || 1;

/** The policy of a configuration whose desired body the compilation refused (compile:body_too_large): the agent keeps
 *  the policy it holds, and still reports it (§8.1). */
export const KEEP_POLICY = { v: 1, keep: true } as const;

/** The audits of a held-back wipe threshold already written (device and hash): once each. */
const withheldAudited = new Set<string>();

/**
 * The configuration of the agent of a device. `agent`: the device and the versionCode the request announces; an agent
 * of REMOTE_LIMITS.minAgentVersionCode at least gets the remote object (P0-15 §4.3), an agent of 1.3.0 at least the key
 * `policy` (lot PONT-POL), an older one the configuration of before. `announced`: the version the agent holds (null at
 * the enrollment: the whole configuration).
 */
export async function agentConfigFor(trx: Knex.Transaction, tenantId: number, agent?: { deviceId: number; versionCode: number },
  announced: number | null = null): Promise<AgentConfigAnswer> {
  const s = await instanceSettings();
  const bridge = legacyAgentRemote();
  const remote = bridge && agent && agent.versionCode >= REMOTE_LIMITS.minAgentVersionCode ? await bridge.config(trx, tenantId, agent.deviceId) : null;
  const knoxId = await knoxSecretIdOf(trx, tenantId);
  const policyAgent = !!agent && agent.versionCode >= LEGACY_AGENT_POLICY_MIN_VERSION_CODE;
  const row = policyAgent ? await policyArtifactRow(trx, tenantId, agent!.deviceId) : null;
  const desired = row?.desired_hash ? String(row.desired_hash).trim() : null;
  // A body the compilation refused (too large) is never delivered: the key carries KEEP_POLICY, so the agent keeps what it applied.
  const fatal = !!row && desired !== null && isCompileError(row);
  const frozen = desired !== null && !fatal ? await tenantFrozen(trx, tenantId, 'legacy_agent') : false;
  const version = versionOf({
    inventorySeconds: s.inventorySeconds, keepAlive: true, knoxSecret: knoxId, minAgentVersionCode: s.minVersionCode,
    ...(remote ? { remote } : {}),
    ...(policyAgent ? { policy: fatal ? `error:${desired}` : desired, ...(desired !== null && !fatal ? { frozen } : {}) } : {}),
  });
  if (announced !== null && announced === version) return { version, config: null, degraded: false, policyDegraded: false, deliveredPolicyHash: null };

  let degraded = false;
  let policyDegraded = false;
  const knox = await knoxKeyOf(trx, tenantId, knoxId);
  if (knox.failed) degraded = true;
  const config: AgentConfig = {
    version, inventorySeconds: s.inventorySeconds, keepAlive: true, ...(knox.failed ? {} : { knoxLicenseKey: knox.value }),
    minAgentVersionCode: s.minVersionCode, ...(remote ? { remote } : {}),
  };
  let deliveredPolicyHash: string | null = null;
  // A body the compilation refused: the key stays (an agent 1.3.0 reads its presence as a server of policies, §8.1),
  // with the marker that keeps what the agent applied; never null, which would remove its policy.
  if (policyAgent && fatal) config.policy = { ...KEEP_POLICY };
  if (policyAgent && !fatal) {
    if (desired === null) config.policy = null;
    else {
      const art = await trx('mdm_artifacts').where({ tenant_id: tenantId, hash: desired }).first('body') as { body: unknown } | undefined;
      if (!art) config.policy = null;
      else {
        const body = typeof art.body === 'string' ? JSON.parse(art.body) : art.body;
        const withhold = frozen ? await frozenWithhold(trx, tenantId, agent!.deviceId, body, row!) : [];
        const r = await renderAgentPolicy(trx, tenantId, agent!.deviceId, desired, body, { withhold });
        config.policy = r.policy;
        if (r.degraded) { degraded = true; policyDegraded = true; } else deliveredPolicyHash = desired;
        if (r.withheld.length) await auditWithheld(trx, tenantId, agent!.deviceId, desired, r.withheld);
      }
    }
  }
  if (degraded) config.version = degradedVersion(version);
  return { version: config.version, config, degraded, policyDegraded, deliveredPolicyHash };
}

async function auditWithheld(trx: Knex.Transaction, tenantId: number, deviceId: number, hash: string, keys: string[]): Promise<void> {
  const k = `${tenantId}:${deviceId}:${hash}`;
  if (withheldAudited.has(k)) return;
  withheldAudited.add(k);
  if (withheldAudited.size > 20_000) withheldAudited.delete(withheldAudited.values().next().value as string);
  const ctx = await audit.fromDbActor(LEGACY_AGENT_ACTOR, tenantId);
  await audit.appendInTx(trx, {
    tenantId, action: 'legacy_agent.wipe_settings_withheld', target: { type: 'device', id: String(deviceId), device: deviceId },
    details: { keys, policyHash: hash.slice(0, 16) },
  }, ctx, { onFailure: 'spool' });
}
