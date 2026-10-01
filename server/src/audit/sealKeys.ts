// The key that signs the seals (docs: audit-durci §6.3, §6.8): an Ed25519
// pair. The private key (PKCS#8 DER, base64) is the vault's instance secret
// audit_seal_signing_key, read at the last moment (coffre R4); the raw public
// key is registered in the database by obligarth.audit_seal_key_register,
// which retires the previous one. Identifier: 16 first hex characters of
// SHA-256(raw public key). At every seal, the public key derived from the
// vault's private key must be the active one; otherwise (secret lost, base
// restored) a new pair is made, registered, journaled (audit.seal_key_rotated,
// reason 'mismatch') and alerted.
import { createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from 'node:crypto';
import type { Knex } from 'knex';
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { db } from '../db';
import { asNone, currentDbContext, type DbActor } from '../db/context';
import { logger } from '../utils/logger';
import { vault } from '../vault';
import { registerInstanceSecretName, isInstanceSecretName } from '../vault/registry';
import { fromJob } from './actor';
import { ED25519_SPKI_PREFIX, ed25519PublicPem, sealKeyId } from './merkle';
import type { AuditWriteContext } from './types';
import { appendInTx } from './writer';

export const SEAL_KEY_SECRET = 'audit_seal_signing_key';
/** The actor the database admits for the key registration (besides a
 *  platform administrator). */
export const SEAL_KEYS_ACTOR: DbActor = { type: 'job', name: 'audit.seal-keys' };

export function registerSealKeySecretName(): void {
  if (!isInstanceSecretName(SEAL_KEY_SECRET)) registerInstanceSecretName(SEAL_KEY_SECRET, 'Ed25519 key that signs the audit seals');
}

export interface SealKey {
  keyId: string;
  publicRaw: Buffer;
  privateKey: KeyObject;
}

export interface SealKeyRow {
  keyId: string;
  publicRaw: Buffer;
  createdAt: Date;
  retiredAt: Date | null;
}

/** The raw public key (32 bytes) of an Ed25519 private key. */
export function publicRawOf(key: KeyObject): Buffer {
  const spki = createPublicKey(key).export({ format: 'der', type: 'spki' }) as Buffer;
  if (spki.length !== 44 || !spki.subarray(0, 12).equals(ED25519_SPKI_PREFIX)) throw new Error('not an Ed25519 key');
  return Buffer.from(spki.subarray(12));
}

export async function activeKeyRow(q: Knex | Knex.Transaction = db): Promise<SealKeyRow | null> {
  const r = await q('audit_seal_keys').whereNull('retired_at').first('key_id', 'public_key', 'created_at', 'retired_at') as
    { key_id: string; public_key: Buffer; created_at: Date; retired_at: Date | null } | undefined;
  return r ? { keyId: r.key_id, publicRaw: r.public_key, createdAt: r.created_at, retiredAt: r.retired_at } : null;
}

export async function allKeyRows(q: Knex | Knex.Transaction = db): Promise<SealKeyRow[]> {
  const rows = await q('audit_seal_keys').orderBy('created_at').select('key_id', 'public_key', 'created_at', 'retired_at') as
    Array<{ key_id: string; public_key: Buffer; created_at: Date; retired_at: Date | null }>;
  return rows.map((r) => ({ keyId: r.key_id, publicRaw: r.public_key, createdAt: r.created_at, retiredAt: r.retired_at }));
}

export function keyRowDto(r: SealKeyRow): { keyId: string; algorithm: 'ed25519'; publicKey: string; publicKeyPem: string; createdAt: string; retiredAt: string | null } {
  return {
    keyId: r.keyId,
    algorithm: 'ed25519',
    publicKey: r.publicRaw.toString('hex'),
    publicKeyPem: ed25519PublicPem(r.publicRaw),
    createdAt: new Date(r.createdAt).toISOString(),
    retiredAt: r.retiredAt ? new Date(r.retiredAt).toISOString() : null,
  };
}

/** The vault's private key, or null (none, unreadable). */
async function readPrivateKey(): Promise<KeyObject | null> {
  const b64 = await vault.getInstanceSecret(SEAL_KEY_SECRET);
  if (!b64) return null;
  try {
    return createPrivateKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'pkcs8' });
  } catch {
    logger.error({ code: 'AUDIT_SEAL_KEY_UNREADABLE' }, 'audit: the seal key of the vault is unreadable');
    return null;
  }
}

/**
 * New pair: the vault's secret replaced, the public key registered (the
 * previous one retired), audit.seal_key_rotated written in the same
 * transaction (P1). In the caller's context: the seal-key job's, or a
 * platform administrator's (the database refuses anyone else).
 */
export async function rotateSealKey(reason: 'initial' | 'mismatch' | 'manual' | 'lost', ctx: AuditWriteContext): Promise<SealKey> {
  const { privateKey } = generateKeyPairSync('ed25519');
  const publicRaw = publicRawOf(privateKey);
  const der = privateKey.export({ format: 'der', type: 'pkcs8' }) as Buffer;
  const previous = await activeKeyRow();
  const userId = ctx.actor.type === 'user' ? Number(ctx.actor.ref.slice(2)) : null;
  const keyId = await db.transaction(async (trx) => {
    await vault.setInstanceSecret(SEAL_KEY_SECRET, der.toString('base64'), { userId }, { trx });
    const res = await trx.raw('SELECT obligarth.audit_seal_key_register(?) AS kid', [publicRaw]) as { rows: Array<{ kid: string }> };
    const kid = String(res.rows[0].kid);
    await appendInTx(trx, {
      tenantId: MASTER_TENANT_ID, action: 'audit.seal_key_rotated',
      target: { type: 'seal_key', id: kid },
      details: { keyId: kid, previousKeyId: previous?.keyId ?? null, reason },
    }, ctx);
    return kid;
  });
  der.fill(0);
  if (keyId !== sealKeyId(publicRaw)) throw new Error('audit: seal key identifier mismatch');
  logger.info({ keyId, previousKeyId: previous?.keyId ?? null, reason }, 'audit: seal key registered');
  return { keyId, publicRaw, privateKey };
}

/**
 * The key that signs now: the active one when the vault's private key matches
 * it; otherwise a new pair (reason 'initial' on a fresh instance, 'mismatch'
 * otherwise, alerted). Runs as the seal-key job (context 'none').
 */
export async function ensureSealKey(o: { requestId?: string } = {}): Promise<SealKey & { created: boolean }> {
  return asNone(SEAL_KEYS_ACTOR, async () => {
    const active = await activeKeyRow();
    const priv = await readPrivateKey();
    if (active && priv && publicRawOf(priv).equals(active.publicRaw)) {
      return { keyId: active.keyId, publicRaw: active.publicRaw, privateKey: priv, created: false };
    }
    const reason = !active && !priv ? 'initial' : 'mismatch';
    if (reason === 'mismatch') {
      logger.error({ code: 'AUDIT_SEAL_KEY_MISMATCH', keyId: active?.keyId ?? null }, 'audit: the seal key of the vault is not the active one: new key');
      const { raiseJobAlert } = await import('../jobs/alerts');
      await raiseJobAlert(SEAL_KEYS_ACTOR, {
        stableKey: 'audit:seal-key-mismatch',
        severity: 'critical',
        title: 'Audit seal key replaced',
        message: 'The seal key in the vault did not match the registered one (lost secret or restored database): a new key signs the seals.',
      });
    }
    const requestId = o.requestId ?? currentDbContext()?.requestId ?? 'boot';
    const key = await rotateSealKey(reason, fromJob({ name: SEAL_KEYS_ACTOR.type === 'job' ? SEAL_KEYS_ACTOR.name : 'audit.seal-keys', requestId }));
    return { ...key, created: true };
  });
}
