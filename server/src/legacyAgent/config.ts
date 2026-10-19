import path from 'node:path';
import { LEGACY_AGENT_POLL_BOUNDS } from '@obligarth/shared';
import { config } from '../config';
import { db } from '../db';
import { asNone } from '../db/context';
import { LEGACY_AGENT_ACTOR } from './actor';

// =============================================================================
// Settings of the Android bridge agent (docs: agent-pont-android §6):
//   LEGACY_AGENT_SIGNERS       environment: SHA-256 fingerprints admitted for a
//                              version of the agent (comma separated, colons
//                              allowed); empty: no version can be uploaded
//   legacy_agent_poll_seconds, legacy_agent_min_version_code,
//   legacy_agent_inventory_seconds   app_config (instance), read through a
//                              30-second cache
//   CUSTOM_DIR/agent-apk/<sha256>.apk   the APKs, stored by content (PB12)
// =============================================================================

/** The fingerprints of LEGACY_AGENT_SIGNERS, lower case without colons; invalid entries are dropped (and logged by
 *  the module at start). */
export function signersFromEnv(raw = process.env.LEGACY_AGENT_SIGNERS ?? ''): { signers: string[]; invalid: number } {
  const out = new Set<string>();
  let invalid = 0;
  for (const part of raw.split(',')) {
    const v = part.trim().replace(/:/g, '').toLowerCase();
    if (!v) continue;
    if (/^[0-9a-f]{64}$/.test(v)) out.add(v); else invalid++;
  }
  return { signers: [...out], invalid };
}

/** Where the APKs are kept (client packages and versions of the agent share the store: by content). */
export function apkDir(): string {
  return path.resolve(process.env.LEGACY_AGENT_APK_DIR || path.join(config.customDir, 'agent-apk'));
}

export const MAX_APK_BYTES = 104_857_600;

export const CONFIG_KEYS = {
  pollSeconds: 'legacy_agent_poll_seconds',
  minVersionCode: 'legacy_agent_min_version_code',
  inventorySeconds: 'legacy_agent_inventory_seconds',
  serverKeySha256: 'legacy_agent_server_key_sha256',
  serverKeyCreatedAt: 'legacy_agent_server_key_created_at',
  serverKeyExportedAt: 'legacy_agent_server_key_exported_at',
} as const;

export interface InstanceSettings { pollSeconds: number; minVersionCode: number; inventorySeconds: number }

const DEFAULTS: InstanceSettings = { pollSeconds: LEGACY_AGENT_POLL_BOUNDS.default, minVersionCode: 0, inventorySeconds: 86_400 };
let cache: { at: number; value: InstanceSettings } | null = null;

const intOf = (v: string | null | undefined, min: number, max: number, dflt: number): number => {
  const n = Number(v);
  return Number.isInteger(n) && n >= min && n <= max ? n : dflt;
};

/** The instance settings (cached 30 s); read in the context 'none' as the agent surface. */
export async function instanceSettings(fresh = false): Promise<InstanceSettings> {
  if (!fresh && cache && Date.now() - cache.at < 30_000) return cache.value;
  const rows = await asNone(LEGACY_AGENT_ACTOR, () => db('app_config')
    .whereIn('key', [CONFIG_KEYS.pollSeconds, CONFIG_KEYS.minVersionCode, CONFIG_KEYS.inventorySeconds]).select('key', 'value')) as
    Array<{ key: string; value: string | null }>;
  const m = new Map(rows.map((r) => [r.key, r.value]));
  const value: InstanceSettings = {
    pollSeconds: intOf(m.get(CONFIG_KEYS.pollSeconds), LEGACY_AGENT_POLL_BOUNDS.min, LEGACY_AGENT_POLL_BOUNDS.max, DEFAULTS.pollSeconds),
    minVersionCode: intOf(m.get(CONFIG_KEYS.minVersionCode), 0, 2_000_000_000, DEFAULTS.minVersionCode),
    inventorySeconds: intOf(m.get(CONFIG_KEYS.inventorySeconds), 3_600, 30 * 86_400, DEFAULTS.inventorySeconds),
  };
  cache = { at: Date.now(), value };
  return value;
}

export function forgetInstanceSettings(): void {
  cache = null;
}
