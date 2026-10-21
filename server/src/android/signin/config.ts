// The sign-in URL of the tenant's Android enterprise (lot AN-F2, sections 6.4, 10.5; AMAPI-R14): signinDetails of the
// enterprise, set by the administrator. The URL is the sign-in page of the tenant on the device surface
// (https://mdm.<domain>/a/<MDM key>/signin): the device opens it with the id of a provisioningInfo once the user
// chose to sign in. The instance builds the detail itself and keeps that object (android_enterprises.signin), never
// what Google answers: Google adds to every SigninDetail an enrollment token valid for the whole enterprise and its QR
// code, which the gateway strips (redact.ts) and nothing here ever reads, stores, logs nor returns.
//   PUT /api/android/enterprise/signin { enabled, allowPersonalUsage? }: enabled needs a linked enterprise, the public
//   base of the device surface (https), the MDM key of the tenant and at least one enabled sign-in URL profile;
//   disabled sends an empty list (Google drops the sign-in token). Audited android.signin_configured.
import {
  ANDROID_SIGNIN_PERSONAL_USAGE, type AndroidSigninConfig, type AndroidSigninConfigRequest, type AndroidSigninPersonalUsage, type AndroidSigninReadiness,
} from '@obligarth/shared';
import { audit } from '../../audit';
import type { AuditWriteContext } from '../../audit/types';
import { appleTenants } from '../../apple/tenants/registry';
import { db } from '../../db';
import { asTenant } from '../../db/context';
import { readEnterprise } from '../enterprises/registry';
import { androidGateway } from '../gateway';
import type { AndroidEnterpriseRef } from '../gateway/names';
import type { AndroidGateway } from '../gateway/types';
import { signinIdentity } from './identity';
import { signinUrlOf } from './rules';

export class SigninConfigError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message = code) {
    super(message);
    this.name = 'SigninConfigError';
    this.status = status;
    this.code = code;
  }
}

let surfaceBase: () => string | null = () => null;
/** The public base of the device surface (https://mdm.<domain>): config.apple.mdmPublicBase of lot C, plugged at the
 *  junction (the same as setByodSurfaceBase); null until then (503 androidSigninSurfaceUnavailable). */
export function setSigninSurfaceBase(fn: () => string | null): void { surfaceBase = fn; }
export const signinSurfaceBase = (): string | null => surfaceBase();

/** The stored configuration (android_enterprises.signin): [] or one detail the instance built. */
interface StoredDetail {
  signinUrl: string;
  allowPersonalUsage: AndroidSigninPersonalUsage;
  configuredAt: string;
}

const isUsage = (v: unknown): v is AndroidSigninPersonalUsage => typeof v === 'string' && (ANDROID_SIGNIN_PERSONAL_USAGE as readonly string[]).includes(v);

/** The stored detail, read back strictly (anything else counts as disabled). */
export function storedDetailOf(v: unknown): StoredDetail | null {
  const list = typeof v === 'string' ? JSON.parse(v) as unknown : v;
  if (!Array.isArray(list) || list.length !== 1) return null;
  const d = list[0] as Record<string, unknown>;
  if (!d || typeof d.signinUrl !== 'string' || !isUsage(d.allowPersonalUsage) || typeof d.configuredAt !== 'string') return null;
  return { signinUrl: d.signinUrl, allowPersonalUsage: d.allowPersonalUsage, configuredAt: d.configuredAt };
}

const viewOf = (d: StoredDetail | null): AndroidSigninConfig => ({
  enabled: !!d, signinUrl: d?.signinUrl ?? null, allowPersonalUsage: d?.allowPersonalUsage ?? null, configuredAt: d?.configuredAt ?? null,
});

const HTTPS_BASE_RE = /^https:\/\/[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?\/?$/;

/** The prerequisites of the flow (lot AN-F2, raccord of 21/10): booleans and counts only, in the tenant's context. */
async function readinessOf(tenantId: number): Promise<AndroidSigninReadiness> {
  const base = surfaceBase();
  const rows = await db('enrollment_profiles as p')
    .leftJoin('android_enrollment_policies as e', function j() { this.on('e.profile_id', '=', 'p.id').andOn('e.tenant_id', '=', 'p.tenant_id'); })
    .where({ 'p.tenant_id': tenantId, 'p.platform': 'android', 'p.method': 'android_signin_url', 'p.enabled': true }).whereNull('p.archived_at')
    .select('e.state') as Array<{ state: string | null }>;
  let identityProvider = false;
  try { identityProvider = !!(await signinIdentity().origin()); } catch { identityProvider = false; }
  return {
    surface: !!base && HTTPS_BASE_RE.test(base), mdmKey: !!(await appleTenants.keyOrNull(tenantId)),
    profiles: rows.length, profilesPushed: rows.filter((r) => r.state === 'pushed').length, identityProvider,
  };
}

/** GET /api/android/enterprise/signin (and the answer of PUT): the configuration and its prerequisites. */
export async function readSigninConfig(tenantId: number, userId: number): Promise<AndroidSigninConfig> {
  return asTenant(tenantId, { type: 'user', userId }, async () => {
    const row = await db('android_enterprises').whereIn('state', ['linked', 'unlinking', 'error']).first('signin') as { signin: unknown } | undefined;
    return { ...viewOf(row ? storedDetailOf(row.signin) : null), readiness: await readinessOf(tenantId) };
  });
}

/** PUT /api/android/enterprise/signin (see the head of this file). */
export async function configureSignin(tenantId: number, userId: number, req: AndroidSigninConfigRequest, auditCtx: AuditWriteContext,
  o: { gateway?: AndroidGateway } = {}): Promise<AndroidSigninConfig> {
  const gw = o.gateway ?? androidGateway();
  if (typeof req?.enabled !== 'boolean') throw new SigninConfigError(400, 'invalidInput');
  const usage = req.allowPersonalUsage ?? 'PERSONAL_USAGE_ALLOWED';
  if (!isUsage(usage)) throw new SigninConfigError(400, 'invalidInput', 'allowPersonalUsage');
  const base = req.enabled ? surfaceBase() : null;
  if (req.enabled && (!base || !HTTPS_BASE_RE.test(base))) {
    throw new SigninConfigError(503, 'androidSigninSurfaceUnavailable', 'the device surface has no public HTTPS base');
  }
  return asTenant(tenantId, { type: 'user', userId }, async () => {
    let detail: StoredDetail | null = null;
    if (base) {
      const key = await appleTenants.keyOrNull(tenantId);
      if (!key) throw new SigninConfigError(409, 'androidMdmKeyMissing', 'the tenant has no MDM key yet');
      detail = { signinUrl: signinUrlOf(base, key), allowPersonalUsage: usage, configuredAt: new Date().toISOString() };
    }
    const e = await readEnterprise();
    if (!e || e.state !== 'linked') throw new SigninConfigError(409, 'androidNotLinked', 'no linked Android enterprise');
    if (detail) {
      const profiles = await db('enrollment_profiles').where({ tenant_id: tenantId, platform: 'android', method: 'android_signin_url', enabled: true })
        .whereNull('archived_at').count<{ n: string }[]>('* as n');
      if (Number(profiles[0]?.n ?? 0) === 0) throw new SigninConfigError(409, 'androidSigninProfileMissing', 'no enabled sign-in URL profile');
    }
    // Outside any transaction (G-A1). The body is the instance's own object; the answer is not read beyond its success.
    const signinDetails = detail
      ? [{ signinUrl: detail.signinUrl, allowPersonalUsage: detail.allowPersonalUsage, defaultStatus: 'SIGNIN_DETAIL_IS_DEFAULT' as const }]
      : [];
    await gw.patchEnterprise(e, { signinDetails }, ['signinDetails']);
    await db.transaction(async (trx) => {
      await trx('android_enterprises').where({ id: e.id }).update({ signin: JSON.stringify(detail ? [detail] : []), updated_at: trx.fn.now() });
      await audit.appendInTx(trx, {
        tenantId, action: 'android.signin_configured', target: { type: 'android_enterprise', id: String(e.id) },
        details: { enabled: !!detail, ...(detail ? { allowPersonalUsage: detail.allowPersonalUsage } : {}) },
      }, auditCtx);
    });
    return viewOf(detail);
  });
}

/**
 * Step 1 of the offboarding of a client (§6.5, lot AN-H1; open point of lot AN-F2, raccord of 21/10): the sign-in URL
 * of an enterprise being unlinked is emptied at Google (signinDetails [], the only patch the gateway admits while
 * unlinking) and in the instance, so that no device is sent to the surface any more. Idempotent: nothing is done for an
 * enterprise without a sign-in URL. Returns true when a configuration was removed (audited android.signin_configured,
 * enabled false, byOffboarding). In the tenant's context of the caller, outside any transaction (G-A1).
 */
export async function clearSigninForOffboarding(gw: AndroidGateway, e: AndroidEnterpriseRef, tenantId: number, auditCtx: AuditWriteContext):
  Promise<boolean> {
  const row = await db('android_enterprises').where({ tenant_id: tenantId, id: e.id }).first('signin') as { signin: unknown } | undefined;
  if (!row || !storedDetailOf(row.signin)) return false;
  await gw.patchEnterprise(e, { signinDetails: [] }, ['signinDetails']);
  await db.transaction(async (trx) => {
    await trx('android_enterprises').where({ tenant_id: tenantId, id: e.id }).update({ signin: JSON.stringify([]), updated_at: trx.fn.now() });
    await audit.appendInTx(trx, {
      tenantId, action: 'android.signin_configured', target: { type: 'android_enterprise', id: String(e.id) },
      details: { enabled: false, byOffboarding: true },
    }, auditCtx);
  });
  return true;
}
