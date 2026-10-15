// Construction and control of the AMAPI resource names (annex C vectors). The gateway never assembles a URL path
// from a received text: every name is built here from identifiers validated against [A-Za-z0-9_-]{1,100} and
// encoded segment by segment; a full name received (an operation of a notification, the policyName of a device)
// must start with the enterprise of the current tenant. Also the signup callback token `s` (256 bits, base64url)
// and its SHA-256. Pure, erasable TypeScript (unit tests under node --test).
import { createHash, randomBytes } from 'node:crypto';
import { AndroidOwnershipError, AndroidRequestError } from './errors';

export const ID_RE = /^[A-Za-z0-9_-]{1,100}$/;
export const ENTERPRISE_NAME_RE = /^enterprises\/([A-Za-z0-9_-]{1,100})$/;
/** Policy ids: d-<device uuid>, e-<profile uuid>, c-<h16>, and the reserved 'default'. */
export const POLICY_ID_RE = /^(d|e|c)-[0-9a-f-]{1,64}$/;
/** Android package names (apps_android_identifier). */
export const PACKAGE_RE = /^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$/;

export type PolicyId = string;

/** The enterprise of the current tenant, as read under RLS: never a name received from a client. */
export interface AndroidEnterpriseRef {
  readonly id: number;
  readonly tenantId: number;
  /** enterprises/{enterpriseId} */
  readonly name: string;
  readonly state: 'linked' | 'unlinking' | 'error' | 'pending' | 'unlinked';
}

/** The id of an identifier received for a resource; AndroidRequestError when malformed (before any call). */
export function checkId(value: unknown, what: string): string {
  if (typeof value !== 'string' || !ID_RE.test(value)) throw new AndroidRequestError(`invalid ${what} identifier`);
  return value;
}

export function enterpriseIdOf(e: Pick<AndroidEnterpriseRef, 'name'>): string {
  const m = ENTERPRISE_NAME_RE.exec(e.name);
  if (!m) throw new AndroidOwnershipError('malformed enterprise of the tenant');
  return m[1];
}

const seg = (s: string): string => encodeURIComponent(s);

export const names = {
  enterprise(e: Pick<AndroidEnterpriseRef, 'name'>): string {
    return `enterprises/${seg(enterpriseIdOf(e))}`;
  },
  device(e: Pick<AndroidEnterpriseRef, 'name'>, deviceId: string): string {
    return `${names.enterprise(e)}/devices/${seg(checkId(deviceId, 'device'))}`;
  },
  operation(e: Pick<AndroidEnterpriseRef, 'name'>, deviceId: string, operationId: string): string {
    return `${names.device(e, deviceId)}/operations/${seg(checkId(operationId, 'operation'))}`;
  },
  enrollmentToken(e: Pick<AndroidEnterpriseRef, 'name'>, tokenId: string): string {
    return `${names.enterprise(e)}/enrollmentTokens/${seg(checkId(tokenId, 'enrollment token'))}`;
  },
  policy(e: Pick<AndroidEnterpriseRef, 'name'>, policyId: string): string {
    return `${names.enterprise(e)}/policies/${seg(checkPolicyId(policyId))}`;
  },
  application(e: Pick<AndroidEnterpriseRef, 'name'>, packageName: string): string {
    if (typeof packageName !== 'string' || packageName.length > 255 || !PACKAGE_RE.test(packageName)) {
      throw new AndroidRequestError('invalid package name');
    }
    return `${names.enterprise(e)}/applications/${seg(packageName)}`;
  },
};

export function checkPolicyId(policyId: unknown): PolicyId {
  if (policyId === 'default') return policyId;
  if (typeof policyId !== 'string' || !POLICY_ID_RE.test(policyId)) throw new AndroidOwnershipError('policy id outside the allowed prefixes');
  return policyId;
}

/**
 * Splits a full name received from Google or a notification and checks that it belongs to `e`:
 * enterprises/{e}/devices/{d}[/operations/{o}], enterprises/{e}/policies/{p}, enterprises/{e}/enrollmentTokens/{t}.
 * AndroidOwnershipError when the enterprise differs or the name is malformed.
 */
export function parseOwnedName(e: Pick<AndroidEnterpriseRef, 'name'>, full: unknown):
  { kind: 'device'; deviceId: string } | { kind: 'operation'; deviceId: string; operationId: string }
  | { kind: 'policy'; policyId: string } | { kind: 'enrollmentToken'; tokenId: string } {
  if (typeof full !== 'string' || full.length > 400) throw new AndroidOwnershipError('malformed resource name');
  const parts = full.split('/');
  if (parts.length < 4 || parts[0] !== 'enterprises' || !ID_RE.test(parts[1])) throw new AndroidOwnershipError('malformed resource name');
  if (parts[1] !== enterpriseIdOf(e)) throw new AndroidOwnershipError('resource of another enterprise');
  for (const p of parts.slice(2)) if (p === '' || p === '.' || p === '..') throw new AndroidOwnershipError('malformed resource name');
  if (parts.length === 4 && parts[2] === 'devices' && ID_RE.test(parts[3])) return { kind: 'device', deviceId: parts[3] };
  if (parts.length === 6 && parts[2] === 'devices' && ID_RE.test(parts[3]) && parts[4] === 'operations' && ID_RE.test(parts[5])) {
    return { kind: 'operation', deviceId: parts[3], operationId: parts[5] };
  }
  if (parts.length === 4 && parts[2] === 'policies') return { kind: 'policy', policyId: checkPolicyId(parts[3]) };
  if (parts.length === 4 && parts[2] === 'enrollmentTokens' && ID_RE.test(parts[3])) return { kind: 'enrollmentToken', tokenId: parts[3] };
  throw new AndroidOwnershipError('malformed resource name');
}

/** The enterprise named at the head of a resource name (notifications), or null. */
export function enterpriseOfResource(full: unknown): string | null {
  if (typeof full !== 'string' || full.length > 400) return null;
  const m = /^(enterprises\/[A-Za-z0-9_-]{1,100})(\/|$)/.exec(full);
  return m ? m[1] : null;
}

// ── Signup callback token `s` (AN33) ─────────────────────────────────────────

const S_RE = /^[A-Za-z0-9_-]{43}$/;

/** A new callback token: 32 random bytes, base64url (43 characters). */
export function newCallbackToken(): { token: string; hash: Buffer } {
  const raw = randomBytes(32);
  const token = raw.toString('base64url');
  const hash = createHash('sha256').update(raw).digest();
  raw.fill(0);
  return { token, hash };
}

/**
 * SHA-256 of the 32 raw bytes of a received token, or null when the token is absent, malformed or not 32 bytes
 * (refused before any query).
 */
export function callbackTokenHash(token: unknown): Buffer | null {
  if (typeof token !== 'string' || !S_RE.test(token)) return null;
  const raw = Buffer.from(token, 'base64url');
  if (raw.length !== 32 || raw.toString('base64url') !== token) { raw.fill(0); return null; }
  const hash = createHash('sha256').update(raw).digest();
  raw.fill(0);
  return hash;
}
