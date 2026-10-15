// Deposit of the service account key (vault_key mode, section 5.2): the key is checked (type, project, account,
// token endpoint), an access token is obtained and the permission on the subscription verified BEFORE anything is
// written; then, in one transaction: sealed in the vault (instance secret android_google_credentials),
// android_platform_state.credential_fingerprint = private_key_id, critical audit entry (fingerprint and account,
// never the key). The key is never read back by a route.
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { audit } from '../audit';
import type { AuditWriteContext } from '../audit/types';
import { db } from '../db';
import { vault } from '../vault';
import { androidConfig, type AndroidConfig } from './config';
import { readPlatformState, updatePlatformState } from './enterprises/registry';
import { AndroidAuthError } from './gateway/errors';
import { androidGateway, GOOGLE_CREDENTIALS_SECRET } from './gateway';
import { GoogleGateway } from './gateway/google';
import { AndroidCredentialError, parseServiceAccountKey } from './google/credentials';

export interface DepositResult { fingerprint: string; account: string; rotated: boolean }

export async function depositServiceAccountKey(text: string, userId: number, auditCtx: AuditWriteContext,
  o: { cfg?: AndroidConfig } = {}): Promise<DepositResult> {
  const cfg = o.cfg ?? androidConfig();
  if (cfg.mode === 'off') throw new AndroidCredentialError('disabled', 'the Android integration is off');
  if (cfg.auth !== 'vault_key') throw new AndroidCredentialError('wrong_mode', 'ANDROID_GOOGLE_AUTH is not vault_key');
  const key = parseServiceAccountKey(text, { projectId: String(cfg.projectId), tokenUrl: cfg.tokenUrl });
  // Before any write: a token, and the permission on the subscription, with this key only.
  const probe = new GoogleGateway(cfg, async () => text);
  let ok = false;
  try {
    ok = await probe.checkSubscription();
  } catch (err) {
    if (err instanceof AndroidAuthError) throw new AndroidCredentialError('token_refused', 'Google refused the key');
    throw err;
  }
  if (!ok) throw new AndroidCredentialError('permission_missing', 'the account lacks pubsub.subscriptions.consume on the subscription');
  const before = await readPlatformState();
  const rotated = !!before.credential_fingerprint && before.credential_fingerprint !== key.privateKeyId;
  await db.transaction(async (trx) => {
    await vault.setInstanceSecret(GOOGLE_CREDENTIALS_SECRET, text, { userId }, { trx });
    await updatePlatformState(trx, { credential_fingerprint: key.privateKeyId, credential_set_at: new Date() });
    await audit.appendInTx(trx, {
      tenantId: MASTER_TENANT_ID,
      action: rotated ? 'android.google_credentials_rotated' : 'android.google_credentials_set',
      target: { type: 'android_identity', id: key.privateKeyId },
      details: rotated
        ? { mode: 'vault_key', previous: before.credential_fingerprint, fingerprint: key.privateKeyId, account: key.clientEmail }
        : { mode: 'vault_key', fingerprint: key.privateKeyId, account: key.clientEmail },
    }, auditCtx);
  });
  const gw = androidGateway();
  if (gw instanceof GoogleGateway) gw.tokens.reset();
  return { fingerprint: key.privateKeyId, account: key.clientEmail, rotated };
}
