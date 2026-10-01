// Errors of the vault (docs: coffre-secrets §5.7). A VaultError names what
// failed and, at most, where: the coordinates of the sealed value (table,
// column, primary key, tenant). Never a value, a ciphertext or key material.
// An error of the vault never falls back on a clear value or on a silent
// "no secret" behaviour: the action that depends on it fails.
import { EnvelopeError } from './envelope';
import type { EnvelopeErrorCode } from './envelope';

export const VAULT_ERROR_CODES = [
  'kek_unavailable',          // no usable KEK (file missing or unreadable, provider down)
  'kek_mismatch',             // a DEK is wrapped by another KEK than the loaded one
  'dek_not_found',            // the kid names no DEK (shredded tenant, foreign ciphertext)
  'dek_destroyed',            // the tenant was crypto-shredded
  'tenant_mismatch',          // the DEK, or the row, belongs to another tenant
  'tenant_retiring',          // writes refused during the 30-day soft deletion
  'format',                   // not a v1 sealed value, or coordinates that make no AAD
  'key_id_mismatch',
  'decrypt_failed',           // authentication failed: wrong AAD, tampering or wrong key
  'too_large',
  'not_registered',           // table/column not declared in the registry
  'operation_not_authorized', // CLI without an authorized vault_operations row
  'server_running',           // offline CLI command while a server holds the online lock
] as const;

export type VaultErrorCode = (typeof VAULT_ERROR_CODES)[number];

/** Coordinates of a sealed value (a SecretLocator fits). */
export interface VaultErrorLocation {
  table: string;
  column: string;
  pk: string | number;
  tenantId: number | null;
}

export class VaultError extends Error {
  readonly code: VaultErrorCode;
  /** Coordinates only: never a value, never a ciphertext. */
  readonly where?: { table: string; column: string; pk: string; tenantId: number | null };

  /** `detail`: a fixed, non-secret explanation (a file path and why it cannot
   *  be used, for instance), never a value. */
  constructor(code: VaultErrorCode, where?: VaultErrorLocation | null, detail?: string) {
    const at = where
      ? { table: where.table, column: where.column, pk: String(where.pk), tenantId: where.tenantId }
      : undefined;
    super(`vault: ${code}`
      + (at ? ` (${at.table}.${at.column}, row ${at.pk}, tenant ${at.tenantId ?? '-'})` : '')
      + (detail ? `: ${detail}` : ''));
    this.name = 'VaultError';
    this.code = code;
    if (at) this.where = at;
  }
}

export function isVaultError(err: unknown, code?: VaultErrorCode): err is VaultError {
  return err instanceof VaultError && (code === undefined || err.code === code);
}

const FROM_ENVELOPE: Record<EnvelopeErrorCode, VaultErrorCode> = {
  format: 'format',
  key_id_mismatch: 'key_id_mismatch',
  decrypt_failed: 'decrypt_failed',
  invalid_key: 'format',      // key material of the wrong size: never a valid DEK
  invalid_aad: 'format',      // coordinates that cannot form an AAD
};

/** An EnvelopeError as the matching VaultError (with the coordinates); any
 *  other error unchanged. Usage: `catch (err) { throw toVaultError(err, loc); }` */
export function toVaultError(err: unknown, where?: VaultErrorLocation | null): unknown {
  if (err instanceof EnvelopeError) return new VaultError(FROM_ENVELOPE[err.code], where);
  return err;
}
