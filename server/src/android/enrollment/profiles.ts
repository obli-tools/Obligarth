// Android enrollment profiles (section 10.1, §4.4 « pas de colonne android_settings »): rows of enrollment_profiles
// with platform = 'android' (the CHECKs admit them from part 3b of the migrations, at the junction), their settings in
// the existing column settings jsonb, validated by the zod schema of this file (deviceUsage, minimumApiLevel,
// kioskApp, googleAuth, requireApproval, approvedSerials). requiredAccountEmail is never stored in a profile. The
// write path of the profiles (the route of lot C1) calls validateAndroidProfile at the junction AN-A2; this lot reads.
import type { Knex } from 'knex';
import { z } from 'zod';
import { PACKAGE_RE } from '../gateway/names';
import {
  EnrollmentRuleError, isAndroidMethod, modeOf, normaliseSerial, tokenPlan,
  type AndroidMethod, type AndroidOwnership, type AndroidUsage, type ProfileSnapshot,
} from './methods';

/** AN25: a company device with personal use (work profile on a company device) from Android 11 only. */
export const COPE_MIN_API = 30;

export const AndroidProfileSettings = z.object({
  deviceUsage: z.enum(['standard', 'kiosk']).default('standard'),
  minimumApiLevel: z.number().int().min(21).max(100).nullable().optional(),
  kioskApp: z.string().max(255).regex(PACKAGE_RE).nullable().optional(),
  googleAuth: z.enum(['UNSPECIFIED', 'OPTIONAL', 'REQUIRED']).default('UNSPECIFIED'),
  requireApproval: z.boolean().optional(),
  approvedSerials: z.array(z.string().max(64)).max(10_000).default([]),
}).strict();
export type AndroidProfileSettings = z.infer<typeof AndroidProfileSettings>;

export interface AndroidProfile {
  id: string;
  tenantId: number;
  name: string;
  method: AndroidMethod;
  ownership: AndroidOwnership;
  defaultGroupId: number | null;
  enabled: boolean;
  settings: AndroidProfileSettings;
}

export interface ProfileIssue { code: string; field: string }

/**
 * The rules of an Android profile (section 10.1, AN25, §4.4): the method and the ownership agree, the kiosk is a
 * company device without personal use, a COPE profile requires API 30 or more (a COPE declared DEVICE_OWNER at
 * API 29 is refused when the profile is written, not at the enrollment), NFC has no COPE. Returns the normalised
 * settings or the issues.
 */
export function validateAndroidProfile(p: { method: unknown; ownership: unknown; settings: unknown }):
  { ok: true; settings: AndroidProfileSettings } | { ok: false; issues: ProfileIssue[] } {
  const issues: ProfileIssue[] = [];
  if (!isAndroidMethod(p.method)) return { ok: false, issues: [{ code: 'androidUnknownMethod', field: 'method' }] };
  const ownership = p.ownership;
  if (ownership !== 'corporate' && ownership !== 'corporate_personal' && ownership !== 'personal') {
    return { ok: false, issues: [{ code: 'invalidOwnership', field: 'ownership' }] };
  }
  const parsed = AndroidProfileSettings.safeParse(p.settings ?? {});
  if (!parsed.success) {
    return { ok: false, issues: parsed.error.issues.slice(0, 20).map((i) => ({ code: 'invalidSetting', field: `settings.${i.path.join('.')}` })) };
  }
  const s = { ...parsed.data };
  if ((p.method === 'android_byod_link') !== (ownership === 'personal') && p.method !== 'android_signin_url') {
    issues.push({ code: 'androidMethodOwnership', field: 'ownership' });
  }
  if (p.method === 'android_nfc' && ownership === 'corporate_personal') issues.push({ code: 'androidMethodOwnership', field: 'ownership' });
  if (s.deviceUsage === 'kiosk') {
    if (ownership !== 'corporate') issues.push({ code: 'androidKioskCorporateOnly', field: 'settings.deviceUsage' });
    if (!s.kioskApp) issues.push({ code: 'androidKioskAppRequired', field: 'settings.kioskApp' });
  } else if (s.kioskApp) {
    issues.push({ code: 'androidKioskAppWithoutKiosk', field: 'settings.kioskApp' });
  }
  if (ownership === 'corporate_personal') {
    if (s.minimumApiLevel === undefined || s.minimumApiLevel === null) s.minimumApiLevel = COPE_MIN_API;
    else if (s.minimumApiLevel < COPE_MIN_API) issues.push({ code: 'androidCopeApiTooLow', field: 'settings.minimumApiLevel' });
  }
  if (s.approvedSerials.some((x) => normaliseSerial(x) === null)) issues.push({ code: 'invalidSerial', field: 'settings.approvedSerials' });
  s.approvedSerials = [...new Set(s.approvedSerials.map((x) => normaliseSerial(x)).filter((x): x is string => x !== null))];
  try {
    tokenPlan({ method: p.method, ownership, usage: s.deviceUsage });
  } catch (err) {
    if (err instanceof EnrollmentRuleError) issues.push({ code: err.code, field: 'method' });
    else throw err;
  }
  return issues.length ? { ok: false, issues } : { ok: true, settings: s };
}

/** The snapshot a token freezes (section 10.2 step 6). */
export function snapshotOf(p: AndroidProfile): ProfileSnapshot {
  const usage: AndroidUsage = p.settings.deviceUsage;
  return {
    profileId: p.id, method: p.method, ownership: p.ownership, mode: modeOf(p.ownership, usage), usage,
    defaultGroupId: p.defaultGroupId, minimumApiLevel: p.settings.minimumApiLevel ?? null,
  };
}

/** Does the token require an approval (AN17): the profile's setting, else the default of the method. */
export function requiresApproval(p: AndroidProfile, approvalByDefault: boolean): boolean {
  return p.settings.requireApproval ?? approvalByDefault;
}

/** A snapshot read back from a token row (jsonb), checked: null when malformed (the token is then unknown). */
export function readSnapshot(v: unknown): ProfileSnapshot | null {
  const o = (typeof v === 'string' ? JSON.parse(v) : v) as Record<string, unknown> | null;
  if (!o || typeof o !== 'object') return null;
  if (!isAndroidMethod(o.method) || typeof o.profileId !== 'string') return null;
  if (!['corporate', 'corporate_personal', 'personal'].includes(String(o.ownership))) return null;
  if (!['fully_managed', 'dedicated', 'work_profile_corporate', 'work_profile_personal'].includes(String(o.mode))) return null;
  return {
    profileId: o.profileId, method: o.method, ownership: o.ownership as AndroidOwnership, mode: o.mode as ProfileSnapshot['mode'],
    usage: o.usage === 'kiosk' ? 'kiosk' : 'standard',
    defaultGroupId: typeof o.defaultGroupId === 'number' ? o.defaultGroupId : null,
    minimumApiLevel: typeof o.minimumApiLevel === 'number' ? o.minimumApiLevel : null,
  };
}

const PROFILE_COLUMNS = ['id', 'tenant_id', 'name', 'platform', 'method', 'ownership', 'default_group_id', 'enabled', 'settings', 'archived_at'];

/** An Android profile of the current tenant (RLS), not archived; null when absent, archived or invalid. */
export async function readAndroidProfile(q: Knex | Knex.Transaction, profileId: string, tenantId: number): Promise<AndroidProfile | null> {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(profileId)) return null;
  const row = await q('enrollment_profiles').where({ id: profileId, tenant_id: tenantId, platform: 'android' }).whereNull('archived_at')
    .first(PROFILE_COLUMNS) as Record<string, unknown> | undefined;
  if (!row) return null;
  const v = validateAndroidProfile({ method: row.method, ownership: row.ownership, settings: row.settings });
  if (!v.ok) return null;
  return {
    id: String(row.id), tenantId: Number(row.tenant_id), name: String(row.name), method: row.method as AndroidMethod,
    ownership: row.ownership as AndroidOwnership, defaultGroupId: row.default_group_id === null ? null : Number(row.default_group_id),
    enabled: row.enabled === true, settings: v.settings,
  };
}
