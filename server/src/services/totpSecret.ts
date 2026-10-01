// The TOTP secret of an account, sealed by the vault (docs: coffre-secrets
// §7.3): users.totp_secret_enc under the instance DEK, AAD
// obligarth.users:totp_secret_enc:<user id>:-. A setup in progress is sealed in
// the session the same way (obligarth.session:pending_totp_secret_enc:<user
// id>:-, transient: unreadable after a rotation of the instance DEK, the user
// starts the setup again). Opened only right before a code is checked.
//
// Invariant kept: enabling, replacing, disabling or resetting a TOTP changes
// totp_secret_enc without the reseal flag, so the trigger
// users_credential_version bumps credential_version (phone keys revoked) as
// before; only the vault's reseal (backfill, DEK rotation) does not.
import { vault, isVaultError, type SecretLocator, type VaultCallOptions } from '../vault';

const totpAt = (userId: number): SecretLocator =>
  ({ table: 'users', column: 'totp_secret_enc', pk: userId, tenantId: null });
const pendingAt = (userId: number): SecretLocator =>
  ({ table: 'session', column: 'pending_totp_secret_enc', pk: userId, tenantId: null });

/** A local TOTP is enabled and its secret present (no value opened). */
export function hasLocalTotp(row: { totp_enabled?: boolean | null; totp_secret_enc?: string | null } | null | undefined): boolean {
  return !!(row?.totp_enabled && row?.totp_secret_enc);
}

export function sealTotpSecret(userId: number, base32: string, o?: VaultCallOptions): Promise<string> {
  return vault.seal(totpAt(userId), base32, o);
}

/** The base32 secret, right before verifyTotpStep / reportTotpDrift. */
export function openTotpSecret(row: { id: number; totp_secret_enc: string }): Promise<string> {
  return vault.openString(totpAt(Number(row.id)), row.totp_secret_enc);
}

/** A setup in progress, kept 10 min in the session. */
export function sealPendingTotpSecret(userId: number, base32: string): Promise<string> {
  return vault.seal(pendingAt(userId), base32);
}

/** null when the sealed value cannot be opened any more (instance DEK
 *  rotated, another account's session value): "TOTP setup expired". */
export async function openPendingTotpSecret(userId: number, sealed: unknown): Promise<string | null> {
  if (typeof sealed !== 'string' || !sealed) return null;
  try {
    return await vault.openString(pendingAt(userId), sealed);
  } catch (err) {
    if (isVaultError(err)) return null;
    throw err;
  }
}
