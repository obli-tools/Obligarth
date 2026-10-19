import { createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { audit, type AuditWriteContext } from '../audit';
import { db } from '../db';
import { asNone, switchToIdentity } from '../db/context';
import { appConfigService } from '../services/appConfig.service';
import { logger } from '../utils/logger';
import { vault } from '../vault';
import { isInstanceSecretName, registerInstanceSecretName } from '../vault/registry';
import { legacyAgentJobActor } from './actor';
import { CONFIG_KEYS } from './config';
import { b64url, keyIdOf, sha256Hex, signMessage } from './signature';

// =============================================================================
// The instance key that signs the answers of the agent surface (docs:
// agent-pont-android §4.3, RS-1, RC-2, RC-3): an EC P-256 pair whose private
// key (PKCS#8 DER, base64) is the vault's instance secret
// legacy_agent_signing_key. Created by the start task legacy-agent.server-key
// when absent on a fresh instance; NEVER replaced on its own: the fleet pins
// its fingerprint (the APK compiles SERVER_KEY_PINS), so a lost key is a lost
// fleet. The fingerprint of the key is kept in app_config at its creation: a
// secret missing while a fingerprint is recorded (restored database, lost
// vault) is reported (critical platform alert) and the surface answers 503
// unavailable, instead of signing with a key no agent trusts. Exportable once
// by a platform administrator (second factor) for the escrow.
// =============================================================================

export const SERVER_KEY_SECRET = 'legacy_agent_signing_key';
const ACTOR = legacyAgentJobActor('legacy-agent.server-key');

export interface ServerKey {
  privateKey: KeyObject;
  spki: Buffer;
  spkiB64url: string;
  sha256: string;
  keyId: string;
}

let loaded: ServerKey | null = null;
let missing = false;

export function registerServerKeySecretName(): void {
  if (!isInstanceSecretName(SERVER_KEY_SECRET)) {
    registerInstanceSecretName(SERVER_KEY_SECRET, 'EC P-256 key that signs the answers to the Android bridge agents (pinned by the fleet)');
  }
}

function fromPkcs8(b64: string): ServerKey {
  const privateKey = createPrivateKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'pkcs8' });
  if (privateKey.asymmetricKeyType !== 'ec' || privateKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
    throw new Error('legacy_agent_signing_key is not an EC P-256 key');
  }
  const spki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' }) as Buffer;
  return { privateKey, spki, spkiB64url: b64url(spki), sha256: sha256Hex(spki), keyId: keyIdOf(spki) };
}

/**
 * At start (and lazily): the vault's key, created on a fresh instance. A secret missing while the fingerprint of a
 * key is recorded is never replaced: `missing` (the surface answers 503) and a critical platform alert.
 */
export async function ensureServerKey(): Promise<{ state: 'loaded' | 'created' | 'missing'; sha256: string | null }> {
  return asNone(ACTOR, async () => {
    const b64 = await vault.getInstanceSecret(SERVER_KEY_SECRET);
    const recorded = await appConfigService.get(CONFIG_KEYS.serverKeySha256);
    if (b64) {
      const key = fromPkcs8(b64);
      if (recorded && recorded !== key.sha256) {
        // The vault holds another key than the one the fleet pinned: refuse to sign with it.
        loaded = null;
        missing = true;
        logger.fatal({ code: 'LEGACY_AGENT_SERVER_KEY_MISMATCH', recorded, vault: key.sha256 }, 'legacy agent: the instance key of the vault is not the one the fleet pins');
        await raiseMissing('The instance key of the vault is not the one the Android agents pin: restore the escrowed key.');
        return { state: 'missing', sha256: recorded };
      }
      if (!recorded) {
        await switchToIdentity(() => db('app_config').insert({ key: CONFIG_KEYS.serverKeySha256, value: key.sha256 }).onConflict('key').ignore());
      }
      loaded = key;
      missing = false;
      return { state: 'loaded', sha256: key.sha256 };
    }
    if (recorded) {
      loaded = null;
      missing = true;
      logger.fatal({ code: 'LEGACY_AGENT_SERVER_KEY_MISSING', recorded }, 'legacy agent: the instance key is missing from the vault; the agents cannot be served');
      await raiseMissing('The instance key that signs the answers to the Android agents is missing from the vault: restore the escrowed key (legacy_agent_signing_key).');
      return { state: 'missing', sha256: recorded };
    }
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const der = privateKey.export({ format: 'der', type: 'pkcs8' }) as Buffer;
    const key = fromPkcs8(der.toString('base64'));
    // The secret first (its own transaction, audited by the vault), then its fingerprint: a stop in between leaves
    // a secret without fingerprint, which the next start records (never a fingerprint without its secret).
    await vault.setInstanceSecret(SERVER_KEY_SECRET, der.toString('base64'), { userId: null });
    await switchToIdentity(async () => {
      await db('app_config').insert({ key: CONFIG_KEYS.serverKeySha256, value: key.sha256 }).onConflict('key').merge({ value: key.sha256 });
      await db('app_config').insert({ key: CONFIG_KEYS.serverKeyCreatedAt, value: new Date().toISOString() }).onConflict('key').merge();
    });
    der.fill(0);
    loaded = key;
    missing = false;
    logger.info({ keyId: key.keyId }, 'legacy agent: instance key created');
    return { state: 'created', sha256: key.sha256 };
  });
}

async function raiseMissing(message: string): Promise<void> {
  const { raiseJobAlert } = await import('../jobs/alerts');
  await raiseJobAlert(ACTOR, { stableKey: 'legacy_agent:server-key-missing', severity: 'critical', title: 'Android agent key missing', message });
}

/** The key that signs now, or null (missing: the surface answers 503). */
export async function currentServerKey(): Promise<ServerKey | null> {
  if (loaded) return loaded;
  if (missing) return null;
  try {
    await ensureServerKey();
  } catch (err) {
    logger.error({ code: (err as { code?: unknown })?.code }, 'legacy agent: instance key not loaded');
    return null;
  }
  return loaded;
}

/** Signs a canonical response string; throws without a key (the caller answered 503 before). */
export function signWith(key: ServerKey, message: string): string {
  return signMessage(key.privateKey, message);
}

/** What the platform console shows: the public key and its fingerprint, never the private key. */
export async function serverKeyView(): Promise<{ keyId: string; spki: string; spkiSha256: string; createdAt: string | null; exportedAt: string | null; missing: boolean }> {
  const key = await currentServerKey();
  const recorded = await appConfigService.get(CONFIG_KEYS.serverKeySha256);
  return {
    keyId: key?.keyId ?? (recorded ? recorded.slice(0, 16) : ''),
    spki: key?.spkiB64url ?? '',
    spkiSha256: key?.sha256 ?? recorded ?? '',
    createdAt: await appConfigService.get(CONFIG_KEYS.serverKeyCreatedAt),
    exportedAt: await appConfigService.get(CONFIG_KEYS.serverKeyExportedAt),
    missing: !key,
  };
}

/**
 * The export for the escrow (RC-3): once, by a platform administrator who passed a strict second factor (the
 * route), journaled in the master tenant before the value leaves (critical). A second export is refused (409).
 */
export async function exportServerKey(ctx: AuditWriteContext): Promise<{ pkcs8: string; spkiSha256: string; exportedAt: string } | 'already_exported' | 'missing'> {
  const key = await currentServerKey();
  if (!key) return 'missing';
  const exportedAt = new Date().toISOString();
  const claimed = await switchToIdentity(() => db.transaction(async (trx) => {
    const row = await trx('app_config').where({ key: CONFIG_KEYS.serverKeyExportedAt }).forUpdate().first('value') as { value: string | null } | undefined;
    if (row?.value) return false;
    await trx('app_config').insert({ key: CONFIG_KEYS.serverKeyExportedAt, value: exportedAt }).onConflict('key').merge({ value: exportedAt });
    await audit.appendInTx(trx, {
      tenantId: MASTER_TENANT_ID, action: 'legacy_agent.server_key_exported',
      target: { type: 'legacy_agent_server_key', id: key.keyId }, details: { keyId: key.keyId, spkiSha256: key.sha256 },
    }, ctx);
    return true;
  }));
  if (!claimed) return 'already_exported';
  const der = key.privateKey.export({ format: 'der', type: 'pkcs8' }) as Buffer;
  const pkcs8 = der.toString('base64');
  der.fill(0);
  return { pkcs8, spkiSha256: key.sha256, exportedAt };
}

/** Tests only: forget the loaded key. */
export function forgetServerKey(): void {
  loaded = null;
  missing = false;
}
