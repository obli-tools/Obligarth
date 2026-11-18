import { createHmac, timingSafeEqual } from 'node:crypto';
import { config } from '../../config';

// =============================================================================
// Opaque cursors of the read API (GET /access-keys; GET /devices in lot L2): base64url of a small JSON position plus
// an HMAC-SHA256 under a key derived from SESSION_SECRET (label 'obliwatch-cursor:v1'), bound to the tenant and the
// endpoint. A cursor of another tenant, another endpoint, or edited by hand is refused (400 cursor_invalid): the
// position never steers a query outside what the caller may read, but a forged one must not even be parsed.
// =============================================================================

const SIG_BYTES = 16;
const MAX_CURSOR_CHARS = 512;

function key(): Buffer {
  return createHmac('sha256', config.sessionSecret || 'obliwatch-cursor-unset').update('obliwatch-cursor:v1').digest();
}

function mac(scope: string, payload: string): Buffer {
  return createHmac('sha256', key()).update(scope).update('\n').update(payload).digest().subarray(0, SIG_BYTES);
}

/** A cursor for `position` (JSON-serialisable), valid only for `tenantId` and `endpoint`. */
export function encodeCursor(tenantId: number, endpoint: string, position: unknown): string {
  const payload = Buffer.from(JSON.stringify(position), 'utf8').toString('base64url');
  return `${payload}.${mac(`${tenantId}|${endpoint}`, payload).toString('base64url')}`;
}

/** The position of a cursor, or null when it is malformed, forged, or of another tenant or endpoint. */
export function decodeCursor<T = unknown>(tenantId: number, endpoint: string, cursor: string): T | null {
  if (typeof cursor !== 'string' || cursor.length === 0 || cursor.length > MAX_CURSOR_CHARS) return null;
  const parts = cursor.split('.');
  if (parts.length !== 2 || !/^[A-Za-z0-9_-]+$/.test(parts[0]) || !/^[A-Za-z0-9_-]+$/.test(parts[1])) return null;
  const given = Buffer.from(parts[1], 'base64url');
  const expected = mac(`${tenantId}|${endpoint}`, parts[0]);
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
  try {
    return JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')) as T;
  } catch {
    return null;
  }
}
