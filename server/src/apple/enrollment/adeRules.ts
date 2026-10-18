import { createHmac } from 'node:crypto';
import type { EnrollmentProfileSettings } from '@obligarth/shared';
import { DEFAULT_SKIP_SETUP_ITEMS } from './settings';
import { sameHash } from './tokens';

// =============================================================================
// Pure rules of the ADE and account-driven enrollments (docs: integration-apple-edge §10.4 to §10.6; lot C2):
// the platform of a MachineInfo's PRODUCT and the comparison of system versions (minOsVersion), the profile of
// the ADE API for an enrollment profile, a Managed Apple Account as compared, the form token of the BYOD web
// view. No database, no configuration: the unit tests run under node --test.
// =============================================================================

/** The platform of a PRODUCT of the MachineInfo (iPhone17,3 → ios; iPad… → ipados); null otherwise. */
export function platformOfProduct(product: unknown): 'ios' | 'ipados' | null {
  if (typeof product !== 'string') return null;
  if (/^(iPhone|iPod)/.test(product)) return 'ios';
  if (/^iPad/.test(product)) return 'ipados';
  return null;
}

/** Compares two dotted versions numerically (17.6 < 17.10; missing parts count 0; a part that is not a number
 *  counts 0). */
export function compareVersions(a: string, b: string): number {
  const pa = String(a).split('.').map((x) => Number.parseInt(x, 10) || 0);
  const pb = String(b).split('.').map((x) => Number.parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

export interface AdeProfileRow {
  id: string;
  name: string;
  usage: string;
  version: number;
  is_default: boolean;
  ownership: string;
  settings: EnrollmentProfileSettings;
}

/** The profile of the ADE API (protocol 10) for an enrollment profile (§10.6). */
export function adeProfileBody(base: string, key: string, tenantUuid: string, p: AdeProfileRow): Record<string, unknown> {
  const s = p.settings ?? {};
  const body: Record<string, unknown> = {
    profile_name: p.name.slice(0, 200),
    url: `${base}/t/${key}/ade/${p.id}/enroll`,
    is_supervised: true,
    is_mandatory: true,
    // Never removable on a company device (§10.1: refused at the saving; ADE profiles are never personal).
    is_mdm_removable: s.mdmRemovable === true && p.ownership === 'personal',
    await_device_configured: true,
    skip_setup_items: s.skipSetupItems ?? DEFAULT_SKIP_SETUP_ITEMS,
    language: s.language ?? 'fr',
    region: s.region ?? 'FR',
    org_magic: tenantUuid,
  };
  if (s.webAuth !== false) body.configuration_web_url = `${base}/t/${key}/ade/${p.id}/web`;
  if (s.department) body.department = s.department;
  if (s.supportPhone) body.support_phone_number = s.supportPhone;
  if (s.supportEmail) body.support_email_address = s.supportEmail;
  return body;
}

/** A Managed Apple Account as compared (lower case, 320 characters at most, one @); null otherwise. */
export function normalizeAccount(v: unknown): string | null {
  if (typeof v !== 'string') return null;
  const a = v.trim().toLowerCase();
  if (a.length < 3 || a.length > 320 || !/^[^\s@<>"']+@[^\s@<>"']+$/.test(a)) return null;
  return a;
}

/** Lifetime of a form token of the BYOD web view. */
export const FORM_TOKEN_TTL_MS = 30 * 60_000;

const formKey = (secret: string): Buffer => createHmac('sha256', String(secret)).update('obligarth.byod-form.v1').digest();
const formMac = (secret: string, key: string, account: string | null, at: string): string =>
  createHmac('sha256', formKey(secret)).update(`${key}\n${account ?? ''}\n${at}`).digest('base64url');

/** The form token of the web view: binds the tenant's key and the account (or none: typed in the page) to the
 *  moment of the page, under a key derived from `secret` (SESSION_SECRET). */
export function newFormToken(secret: string, key: string, account: string | null, now = Date.now()): string {
  const at = Math.floor(now / 1000).toString(36);
  return `${at}.${formMac(secret, key, account, at)}`;
}

/** Is `token` a form token of this key and account, of the last 30 minutes? */
export function checkFormToken(secret: string, token: unknown, key: string, account: string | null, now = Date.now()): boolean {
  if (typeof token !== 'string' || token.length > 80) return false;
  const m = /^([0-9a-z]{1,10})\.([A-Za-z0-9_-]{43})$/.exec(token);
  if (!m) return false;
  const at = Number.parseInt(m[1], 36) * 1000;
  if (!Number.isFinite(at) || at > now + 60_000 || now - at > FORM_TOKEN_TTL_MS) return false;
  return sameHash(formMac(secret, key, account, m[1]), m[2]);
}
