import { closeSync, constants as fsConstants, fstatSync, openSync, readSync } from 'node:fs';
import { parseHmacKey } from './hmac';

// =============================================================================
// The two secrets the brain shares with apple-edge (docs: integration-apple-
// edge §5.1, annex A; apple-edge §5.2, §11.5), read from their files (Docker
// secrets), never from an environment variable, never logged:
//   - the bearer token of the internal API (APPLE_EDGE_API_TOKEN_FILE, secret
//     apple_edge_api_token): 43 characters at least (32 bytes in base64url);
//   - the key of the DDM relay (APPLE_EDGE_DDM_HMAC_KEY_FILE, secret
//     apple_edge_ddm_hmac; APPLE_EDGE_DDM_HMAC_KEY_NEXT_FILE during a
//     rotation): base64 of 32 bytes at least.
// The messages name the variable and the file, never the content. Self-
// contained (node:fs only): the unit tests run under node --test.
// =============================================================================

/** apple-edge's minimum (api.MinTokenLength). */
export const MIN_TOKEN_LENGTH = 43;
/** Largest secret file read. */
const MAX_FILE_BYTES = 4096;

export class AppleSecretError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AppleSecretError';
  }
}

/** The content of a small regular file; the messages never carry it. */
export function readSecretFile(file: string, setting: string): string {
  if (!file) throw new AppleSecretError(`${setting} is not set`);
  let fd: number;
  try {
    // O_NONBLOCK: a named pipe is refused below (not a regular file) instead of blocking the start.
    fd = openSync(file, fsConstants.O_RDONLY | (fsConstants.O_NONBLOCK ?? 0));
  } catch (err) {
    const code = (err as { code?: string }).code;
    throw new AppleSecretError(`${setting} ${file}: ${code === 'ENOENT' ? 'no such file' : code === 'EISDIR' ? 'not a regular file'
      : code === 'EACCES' || code === 'EPERM' ? 'permission denied' : 'unreadable'}`);
  }
  const buf = Buffer.alloc(MAX_FILE_BYTES + 1);
  let size = 0;
  try {
    if (!fstatSync(fd).isFile()) throw new AppleSecretError(`${setting} ${file}: not a regular file`);
    for (;;) {
      const n = readSync(fd, buf, size, buf.length - size, null);
      if (n === 0) break;
      size += n;
      if (size > MAX_FILE_BYTES) throw new AppleSecretError(`${setting} ${file}: too large for a secret file`);
    }
  } finally {
    closeSync(fd);
  }
  const text = buf.subarray(0, size).toString('utf8');
  buf.fill(0);
  return text;
}

/** The bearer token of the internal API. */
export function readApiTokenFile(file: string, setting = 'APPLE_EDGE_API_TOKEN_FILE'): string {
  const token = readSecretFile(file, setting).trim();
  if (token.length < MIN_TOKEN_LENGTH) {
    throw new AppleSecretError(`${setting} ${file}: the token is shorter than ${MIN_TOKEN_LENGTH} characters (32 random bytes in base64url)`);
  }
  if (/[\s\0-\x1f\x7f]/.test(token)) throw new AppleSecretError(`${setting} ${file}: the token holds spaces or control characters`);
  return token;
}

/** The key of the DDM relay. */
export function readHmacKeyFile(file: string, setting = 'APPLE_EDGE_DDM_HMAC_KEY_FILE'): Buffer {
  const text = readSecretFile(file, setting);
  try {
    return parseHmacKey(text);
  } catch (err) {
    throw new AppleSecretError(`${setting} ${file}: ${(err as Error).message}`);
  }
}
