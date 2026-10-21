// Rules of the sign-in URL flow (lot AN-F2, section 10.5, §22.3; SEC-AN-1), pure: the id of a provisioningInfo given
// to the sign-in URL, the facts the instance keeps from it (mode, ownership, API level, model: nothing else), the
// profile chosen by rule for those facts, the hashed forms of the state, of the cookie's nonce and of the provisioning
// id, the sign-in URL of a tenant. No database, no logger: the unit tests load it.
import { createHash, randomBytes } from 'node:crypto';
import type { AmapiProvisioningInfoMin } from '@obligarth/shared';
import type { AndroidOwnership, AndroidUsage } from '../enrollment/methods';

const ID_RE = /^[A-Za-z0-9_-]{1,100}$/;

/** The id of a provisioningInfo as the device gives it (a bare id, or provisioningInfo/<id>), or null. */
export function provisioningIdOf(v: unknown): string | null {
  if (typeof v !== 'string' || v.length > 120) return null;
  const id = v.startsWith('provisioningInfo/') ? v.slice('provisioningInfo/'.length) : v;
  return ID_RE.test(id) ? id : null;
}

/** What the instance keeps of a provisioningInfo (the gateway already dropped the IMEI, the MEID and the serial
 *  number): the mode, the ownership, the API level and the model. The e-mail is never kept. */
export interface ProvisioningFacts {
  managementMode: 'DEVICE_OWNER' | 'PROFILE_OWNER';
  ownership: 'COMPANY_OWNED' | 'PERSONALLY_OWNED';
  apiLevel: number | null;
  model: string | null;
}

/** The facts of a reduced provisioningInfo, or null when its mode or its ownership is not one the instance handles. */
export function factsOf(info: AmapiProvisioningInfoMin): ProvisioningFacts | null {
  const mode = info.managementMode;
  const own = info.ownership;
  if (mode !== 'DEVICE_OWNER' && mode !== 'PROFILE_OWNER') return null;
  if (own !== 'COMPANY_OWNED' && own !== 'PERSONALLY_OWNED') return null;
  // A personal device is never fully managed.
  if (own === 'PERSONALLY_OWNED' && mode !== 'PROFILE_OWNER') return null;
  const api = Number.isInteger(info.apiLevel) && Number(info.apiLevel) > 0 && Number(info.apiLevel) <= 1000 ? Number(info.apiLevel) : null;
  const model = typeof info.model === 'string' && info.model.trim() ? info.model.trim().slice(0, 64) : null;
  return { managementMode: mode, ownership: own, apiLevel: api, model };
}

/** The ownership of the instance for the facts: personal, COPE (work profile on a company device) or fully managed. */
export function ownershipOfFacts(f: ProvisioningFacts): AndroidOwnership {
  if (f.ownership === 'PERSONALLY_OWNED') return 'personal';
  return f.managementMode === 'PROFILE_OWNER' ? 'corporate_personal' : 'corporate';
}

export interface SigninCandidate {
  id: string;
  method: string;
  ownership: AndroidOwnership;
  usage: AndroidUsage;
  enabled: boolean;
  minimumApiLevel: number | null;
  /** Order of the rule: the profiles are read oldest first (created_at, id). */
  rank: number;
}

/**
 * The profile of a device of the sign-in flow (« profil choisi par règle »): an enabled sign-in URL profile of the
 * tenant whose ownership is the device's (personal ⇔ PERSONALLY_OWNED; COPE ⇔ COMPANY_OWNED and PROFILE_OWNER; fully
 * managed ⇔ COMPANY_OWNED and DEVICE_OWNER), never a kiosk (nobody signs in on a device without user), whose minimum
 * API level the device reaches (an unknown API level never passes a minimum: fail closed). Several: the oldest. None:
 * null (the device is sent to the invalid page).
 */
export function chooseSigninProfile(candidates: readonly SigninCandidate[], f: ProvisioningFacts): SigninCandidate | null {
  const ownership = ownershipOfFacts(f);
  const ok = candidates.filter((c) => c.enabled && c.method === 'android_signin_url' && c.usage !== 'kiosk' && c.ownership === ownership
    && (c.minimumApiLevel === null || (f.apiLevel !== null && f.apiLevel >= c.minimumApiLevel)));
  ok.sort((a, b) => a.rank - b.rank);
  return ok[0] ?? null;
}

/** Is allowPersonalUsage of the enterprise's signinDetails compatible with the facts? PERSONAL_USAGE_DISALLOWED
 *  admits fully managed company devices only; PERSONAL_USAGE_ALLOWED a work profile (COPE or personal) only, a company
 *  device announced as DEVICE_OWNER included (see signinFacts). */
export function usageAdmits(allowPersonalUsage: string | null, f: ProvisioningFacts): boolean {
  if (allowPersonalUsage === 'PERSONAL_USAGE_DISALLOWED') return f.ownership === 'COMPANY_OWNED' && f.managementMode === 'DEVICE_OWNER';
  if (allowPersonalUsage === 'PERSONAL_USAGE_ALLOWED') return f.managementMode === 'PROFILE_OWNER' || f.ownership === 'COMPANY_OWNED';
  return false;
}

/**
 * The facts the flow works with (lot AN-F2, raccord of 21/10; review AN-F2, R7 [AR]): under PERSONAL_USAGE_ALLOWED a
 * company device sets up a work profile (Google, SigninDetail.allowPersonalUsage: « for company-owned devices, enabling
 * personal usage allows the user to set up a work profile »), whatever provisioningInfo announced before the token
 * decided: a company device announced as DEVICE_OWNER is taken as the COPE it will become (PROFILE_OWNER), so that the
 * COPE by sign-in URL is not lost. Nothing is trusted more for it: the token carries PERSONAL_USAGE_ALLOWED and the
 * profile snapshot of a COPE, and the enrollment handler compares the mode of the enrolled Device with that snapshot
 * (a fully managed device enrolled with it is quarantined, section 10.4 step 4). Any other combination: unchanged.
 */
export function signinFacts(f: ProvisioningFacts, allowPersonalUsage: string | null): ProvisioningFacts {
  if (allowPersonalUsage === 'PERSONAL_USAGE_ALLOWED' && f.ownership === 'COMPANY_OWNED' && f.managementMode === 'DEVICE_OWNER') {
    return { ...f, managementMode: 'PROFILE_OWNER' };
  }
  return f;
}

const sha = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex');
/** Hash of a provisioning id, bound to the tenant (one session per provisioning). */
export const provisioningHash = (tenantUuid: string, id: string): string => sha(`oap:${tenantUuid}:${id}`);
/** Hash of the state of an authorization request, bound to the tenant. */
export const stateHash = (tenantUuid: string, state: string): string => sha(`oas:${tenantUuid}:${state}`);
/** Hash of the nonce of the browser cookie. */
export const nonceHash = (nonce: string): string => sha(`oan:${nonce}`);
/** 256 random bits, base64url (state, nonce). */
export const randomToken = (): string => randomBytes(32).toString('base64url');
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
export const isRandomToken = (v: unknown): v is string => typeof v === 'string' && TOKEN_RE.test(v);
/** An authorization code of Obligate as it may arrive (bounded, printable). */
export const isAuthCode = (v: unknown): v is string => typeof v === 'string' && /^[A-Za-z0-9._~+/=-]{8,512}$/.test(v);

/** The sign-in URL of a tenant on the device surface (signinDetails[].signinUrl), and its callback. */
export const signinUrlOf = (base: string, key: string): string => `${base.replace(/\/+$/, '')}/a/${key}/signin`;
export const signinCallbackOf = (base: string, key: string): string => `${signinUrlOf(base, key)}/callback`;
/** The name of the cookie that binds the answer of Obligate to the browser that asked. */
export const SIGNIN_COOKIE = 'obg_signin';
