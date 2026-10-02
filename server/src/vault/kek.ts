// Key-encryption key providers (docs: coffre-secrets §5.3, §9.1). The KEK of
// the server wraps its data keys (DEKs); it never leaves the process, never
// goes to the database, an environment variable or a log. At the MVP it is a
// Docker secret file read at start-up (FileKekProvider); OpenBao or Vault
// Transit comes in v1 behind the same interface (§9.4).
//
// In operation, the server accepts only the current KEK, like apple-edge
// (Keyring.unwrap): the previous one is read by the rotation command only.
//
// No database import, and only what Node's native type stripping runs: the
// unit tests run under `node --test`. Every error is a VaultError.
import fs from 'node:fs';
import { aad, seal, open, kekIdOf, parseKek, EnvelopeError, KEY_BYTES, VAULT_NAMESPACE } from './envelope';
import { VaultError, toVaultError } from './errors';
import type { VaultConfig } from './config';

export interface KekProvider {
  readonly kind: 'file' | 'transit';
  /** kek_id written in data_keys for the DEKs this provider wraps. */
  readonly id: string;
  wrap(dekId: string, tenantId: number | null, dek: Buffer): Promise<string>;
  /** Throws VaultError('kek_mismatch') when kekId is not this provider's. The
   *  returned DEK is the caller's (fill(0) when evicted). */
  unwrap(dekId: string, tenantId: number | null, wrapped: string, kekId: string): Promise<Buffer>;
  /** Zeroes the key material (SIGTERM, end of a CLI command); every later
   *  call fails with kek_unavailable. */
  dispose(): void;
}

/** AAD of a wrapped DEK: obligarth.data_keys:dek_wrapped:<dek id>:<tenant id or ->. */
export function wrapAad(dekId: string, tenantId: number | null): Buffer {
  if (tenantId !== null && !(Number.isSafeInteger(tenantId) && tenantId > 0)) throw new EnvelopeError('invalid_aad');
  return aad(`${VAULT_NAMESPACE}.data_keys`, 'dek_wrapped', dekId, tenantId === null ? null : String(tenantId));
}

/** Coordinates of a wrapped DEK, for the errors. */
function wrappedAt(dekId: string, tenantId: number | null) {
  return { table: 'data_keys', column: 'dek_wrapped', pk: dekId, tenantId };
}

/** The KEK is a Docker secret file read once at start-up (MVP). */
export class FileKekProvider implements KekProvider {
  readonly kind = 'file' as const;
  readonly id: string;
  // A private field: never serialized (JSON, pino) nor shown by util.inspect.
  #key: Buffer | null;

  /** Takes ownership of kek.key (as returned by parseKek or readKekFile). */
  constructor(kek: { id: string; key: Buffer }) {
    if (!Buffer.isBuffer(kek.key) || kek.key.length !== KEY_BYTES || kekIdOf(kek.key) !== kek.id) {
      throw new VaultError('kek_unavailable', null, 'invalid key material');
    }
    this.id = kek.id;
    this.#key = kek.key;
  }

  async wrap(dekId: string, tenantId: number | null, dek: Buffer): Promise<string> {
    const key = this.#current();
    const at = wrappedAt(dekId, tenantId);
    if (!Buffer.isBuffer(dek) || dek.length !== KEY_BYTES) throw new VaultError('format', at);
    try {
      return seal(key, this.id, wrapAad(dekId, tenantId), dek);
    } catch (err) {
      throw toVaultError(err, at);
    }
  }

  async unwrap(dekId: string, tenantId: number | null, wrapped: string, kekId: string): Promise<Buffer> {
    const key = this.#current();
    const at = wrappedAt(dekId, tenantId);
    if (kekId !== this.id) throw new VaultError('kek_mismatch', at);
    let dek: Buffer;
    try {
      dek = open(key, this.id, wrapAad(dekId, tenantId), wrapped);
    } catch (err) {
      throw toVaultError(err, at);
    }
    if (dek.length !== KEY_BYTES) {
      dek.fill(0);
      throw new VaultError('format', at);
    }
    return dek;
  }

  dispose(): void {
    if (this.#key) {
      this.#key.fill(0);
      this.#key = null;
    }
  }

  // After dispose(), never a zeroed key: wrapping under it would expose the DEK.
  #current(): Buffer {
    if (!this.#key) throw new VaultError('kek_unavailable', null, 'the KEK provider was disposed');
    return this.#key;
  }
}

/** A KEK file holds the base64 of 32 bytes (44 characters, a newline at most):
 *  a larger file is not a KEK, and is not read whole. */
const KEK_FILE_MAX_BYTES = 1024;

export type KekFileCheck =
  | { ok: true; kek: { id: string; key: Buffer }; mode: number }
  | { ok: false; reason: string };

function fileError(err: unknown): string {
  const code = typeof err === 'object' && err !== null ? (err as { code?: unknown }).code : undefined;
  if (code === 'ENOENT' || code === 'ENOTDIR') return 'no such file';
  if (code === 'EACCES' || code === 'EPERM') return 'permission denied';
  if (code === 'EISDIR') return 'not a regular file';
  return typeof code === 'string' ? `cannot be read (${code})` : 'cannot be read';
}

/** True when a setting meant to name a KEK file holds a key instead (the KEK
 *  pasted into SERVER_KEK_FILE, say): 32 bytes in base64, whitespace
 *  included, or in hex (openssl rand -hex 32). Such a value is never
 *  repeated: not in a refusal, an error or a log line. */
export function looksLikeKek(value: string): boolean {
  if (typeof value !== 'string') return false;
  const compact = value.replace(/\s+/g, '');
  if (/^[0-9A-Fa-f]{64}$/.test(compact)) return true;
  try {
    parseKek(compact).key.fill(0);
    return true;
  } catch {
    return false;
  }
}

/** The path of a KEK file as messages show it: never a value that looks like
 *  a key. */
export function printableKekPath(file: string): string {
  if (!file) return '(none)';
  return looksLikeKek(file) ? '(a key instead of a path, not shown)' : file;
}

/** Reads and parses a KEK file; on failure, why (fixed words, never the
 *  content). `mode`: the file's mode bits, for the permission warning. The
 *  key, when returned, is the caller's (fill(0) once used). */
export function inspectKekFile(file: string): KekFileCheck {
  if (!file) return { ok: false, reason: 'no file configured' };
  // A key where its path is expected: refused, never used as a file name.
  if (looksLikeKek(file)) return { ok: false, reason: 'the setting holds a key instead of the path of a file' };
  let fd: number;
  try {
    // O_NONBLOCK (lot A8, review of lot A2): a named pipe given as the KEK file is refused below (not a
    // regular file) instead of blocking the start until a writer opens it. Unknown to Windows: 0.
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0));
  } catch (err) {
    return { ok: false, reason: fileError(err) };
  }
  const buf = Buffer.alloc(KEK_FILE_MAX_BYTES + 1);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) return { ok: false, reason: 'not a regular file' };
    let size = 0;
    for (;;) {
      const n = fs.readSync(fd, buf, size, buf.length - size, null);
      if (n === 0) break;
      size += n;
      if (size === buf.length) break;
    }
    if (size > KEK_FILE_MAX_BYTES) return { ok: false, reason: 'too large for a KEK file' };
    let kek: { id: string; key: Buffer };
    try {
      kek = parseKek(buf.toString('utf8', 0, size));
    } catch {
      return { ok: false, reason: 'not a base64-encoded 32-byte key' };
    }
    return { ok: true, kek, mode: st.mode };
  } catch (err) {
    return { ok: false, reason: fileError(err) };
  } finally {
    buf.fill(0);
    try { fs.closeSync(fd); } catch { /* already closed */ }
  }
}

/** The KEK of a file, or VaultError('kek_unavailable') saying why. */
export function readKekFile(file: string): { id: string; key: Buffer } {
  const check = inspectKekFile(file);
  if (!check.ok) throw new VaultError('kek_unavailable', null, `KEK file ${printableKekPath(file)}: ${check.reason}`);
  return check.kek;
}

/** The provider of the configuration: the file KEK at the MVP; Transit (v1,
 *  coffre-secrets §9.4) is refused. vaultConfigErrors() has checked the
 *  configuration before. */
export function loadKekProvider(cfg: VaultConfig): KekProvider {
  if (cfg.provider !== 'file') {
    throw new VaultError('kek_unavailable', null, 'only the file KEK provider is available in this version');
  }
  return new FileKekProvider(readKekFile(cfg.kekFile));
}
