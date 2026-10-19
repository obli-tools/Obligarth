// Fields the gateway strips from Google's answers before any write or response (section 5.4, step 6):
//   - signinEnrollmentToken and qrCode of every SigninDetail (tokens valid for the whole enterprise);
//   - value and qrCode of the enrollment tokens of a list (partial view);
//   - provisioningInfo: refused when its enterprise is not the tenant's, then reduced to six fields (never imei,
//     meid nor serialNumber).
// Pure, erasable TypeScript.
import type { AmapiEnrollmentToken, AmapiEnterprise, AmapiProvisioningInfoMin } from '@obligarth/shared';
import { AndroidNotFoundError } from './errors';

export function redactEnterprise<T extends Partial<AmapiEnterprise>>(e: T): T {
  if (!e || typeof e !== 'object') return e;
  const out = { ...e } as T & { signinDetails?: unknown };
  if (Array.isArray(out.signinDetails)) {
    out.signinDetails = out.signinDetails.map((d) => {
      if (!d || typeof d !== 'object') return d;
      const { signinEnrollmentToken: _t, qrCode: _q, ...rest } = d as Record<string, unknown>;
      return rest;
    });
  }
  return out;
}

export function redactTokenListItem(t: Partial<AmapiEnrollmentToken>): Pick<AmapiEnrollmentToken, 'name' | 'expirationTimestamp' | 'allowPersonalUsage'> {
  return {
    name: String(t?.name ?? ''),
    ...(typeof t?.expirationTimestamp === 'string' ? { expirationTimestamp: t.expirationTimestamp } : {}),
    ...(typeof t?.allowPersonalUsage === 'string' ? { allowPersonalUsage: t.allowPersonalUsage } : {}),
  };
}

const PROVISIONING_FIELDS = ['managementMode', 'ownership', 'apiLevel', 'brand', 'model', 'authenticatedUserEmail'] as const;

/** The reduced provisioningInfo, or AndroidNotFoundError when it belongs to another enterprise. */
export function redactProvisioningInfo(info: Record<string, unknown> | null | undefined, enterpriseName: string): AmapiProvisioningInfoMin {
  if (!info || typeof info !== 'object' || info.enterprise !== enterpriseName) throw new AndroidNotFoundError('provisioning info not found');
  const out: Record<string, unknown> = {};
  for (const k of PROVISIONING_FIELDS) if (info[k] !== undefined) out[k] = info[k];
  return out as AmapiProvisioningInfoMin;
}

/** Keys never written to a log line by the Android code (G-A4, U-A11): tokens, keys, device identifiers. */
export const ANDROID_LOG_FORBIDDEN_KEYS: readonly string[] = [
  'value', 'qrCode', 'signinEnrollmentToken', 'enterpriseToken', 's', 'access_token', 'accessToken', 'private_key',
  'privateKey', 'assertion', 'imei', 'meid', 'serialNumber', 'iccid', 'phoneNumber', 'enrollmentTokenData', 'payload',
  'data', 'authorization', 'newPassword',
];

/** A log-safe copy of `fields`: forbidden keys dropped at any depth, strings bounded. */
export function logSafe(fields: Record<string, unknown>, depth = 0): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(fields ?? {})) {
    if (ANDROID_LOG_FORBIDDEN_KEYS.includes(k)) continue;
    if (v && typeof v === 'object' && !Array.isArray(v) && depth < 3) out[k] = logSafe(v as Record<string, unknown>, depth + 1);
    else if (typeof v === 'string') out[k] = v.slice(0, 200);
    else if (typeof v === 'number' || typeof v === 'boolean' || v === null) out[k] = v;
  }
  return out;
}
