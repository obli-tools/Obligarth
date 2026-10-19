// The long tokens of the company enrollments without a QR code (lot AN-F2, sections 10.1, 10.5, §22.3; AN17):
//   - zero-touch: the zero-touch iframe (enterprises.webTokens with ZERO_TOUCH_CUSTOMER_MANAGEMENT only, never empty,
//     never mixed with a Play feature), hosted by one console page; the default configuration the administrator
//     creates in it carries the extras of an active zero-touch token of the tenant (dpcExtras);
//   - Samsung Knox Mobile Enrollment: the custom JSON of the Knox profile, the enrollment token of an active KME token of
//     the tenant and nothing else (no Wi-Fi password, no account, no other extra: it is copied out of Obligarth);
// both answered once, in the body only (Cache-Control no-store, step-up at the route: a long token enrolls devices for
// a year), never stored, logged nor audited (the audit names the token, never its value). The enrollment policy of
// the profile carries no $secret (refused by the compiler and at the push, §22.3): a device of a long token receives
// nothing secret before its approval (requires_approval, true by default for zero-touch and KME, AN17).
import {
  ANDROID_DPC_PACKAGE, ANDROID_ENROLLMENT_TOKEN_EXTRA, ANDROID_ZERO_TOUCH_FEATURES, ANDROID_ZERO_TOUCH_PAGE, androidProvisioningExtras,
  androidZeroTouchIframeUrl, type AndroidKmeConfiguration, type AndroidZeroTouchIframe,
} from '@obligarth/shared';
import type { Knex } from 'knex';
import { audit } from '../../audit';
import type { AuditWriteContext } from '../../audit/types';
import { db } from '../../db';
import { asTenant } from '../../db/context';
import { vault } from '../../vault';
import { androidConfig } from '../config';
import { readEnterprise } from '../enterprises/registry';
import { androidGateway } from '../gateway';
import type { AndroidGateway, IframeFeature } from '../gateway/types';
import type { AndroidTokenKind } from './methods';
import { TokenError } from './tokens';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Warning keys the console translates (androidWarnings.*). */
export const LONG_TOKEN_WARNINGS = {
  zeroTouchUnlink: 'androidZeroTouchUnlinkRemovesConfig',
  noApproval: 'androidLongTokenWithoutApproval',
  kmeBeforeZeroTouch: 'androidKmeBeforeZeroTouch',
} as const;

interface LongTokenRow {
  id: string;
  kind: AndroidTokenKind;
  state: string;
  value_ref: string | null;
  expires_at: Date;
  requires_approval: boolean;
  max_uses: number | null;
  profile_id: string;
}

/**
 * The value of an active long token of `kind` of the current tenant (RLS), its enrollment policy pushed (secret-free:
 * a policy refused for a $secret is in error, never pushed). 404 for a token of another tenant, of another kind, or no
 * longer active; 409 androidEnrollmentPolicyMissing when the policy of its profile is not pushed.
 */
async function longTokenValue(trx: Knex.Transaction, tenantId: number, tokenId: unknown, kind: 'zero_touch' | 'kme'):
  Promise<{ row: LongTokenRow; value: Buffer }> {
  if (typeof tokenId !== 'string' || !UUID_RE.test(tokenId)) throw new TokenError(404, 'notFound', 'no active token');
  const row = await trx('android_enrollment_tokens').where({ tenant_id: tenantId, id: tokenId })
    .first('id', 'kind', 'state', 'value_ref', 'expires_at', 'requires_approval', 'max_uses', 'profile_id') as LongTokenRow | undefined;
  if (!row || row.kind !== kind || row.state !== 'active' || !row.value_ref || row.max_uses !== null
    || new Date(row.expires_at).getTime() <= Date.now()) {
    throw new TokenError(404, 'notFound', 'no active token');
  }
  const pol = await trx('android_enrollment_policies').where({ profile_id: row.profile_id }).first('state') as { state: string } | undefined;
  if (pol?.state !== 'pushed') throw new TokenError(409, 'androidEnrollmentPolicyMissing', 'the enrollment policy of the profile is not pushed');
  const value = await vault.readTenantSecret(tenantId, row.value_ref, { trx });
  return { row, value };
}

/** The custom JSON of a KME profile: exactly one key, the enrollment token (a check of the instance's own output). */
export function kmeCustomJson(tokenValue: string): string {
  if (!tokenValue || /[\u0000-\u001f]/.test(tokenValue)) throw new TokenError(502, 'androidInvalidRequest', 'token without a value');
  const json = androidProvisioningExtras(tokenValue);
  const parsed = JSON.parse(json) as Record<string, unknown>;
  if (Object.keys(parsed).length !== 1 || parsed[ANDROID_ENROLLMENT_TOKEN_EXTRA] !== tokenValue) {
    throw new TokenError(500, 'androidInvalidRequest', 'unexpected provisioning extras');
  }
  return json;
}

/** GET /api/android/enrollment-tokens/:id/kme (see the head of this file). Audited android.kme_configuration_shown. */
export async function kmeConfiguration(tenantId: number, userId: number, tokenId: string, auditCtx: AuditWriteContext): Promise<AndroidKmeConfiguration> {
  return asTenant(tenantId, { type: 'user', userId }, () => db.transaction(async (trx) => {
    const e = await readEnterprise(trx);
    if (!e || e.state !== 'linked') throw new TokenError(409, 'androidNotLinked', 'no linked Android enterprise');
    const { row, value } = await longTokenValue(trx, tenantId, tokenId, 'kme');
    try {
      const customJson = kmeCustomJson(value.toString('utf8'));
      await audit.appendInTx(trx, {
        tenantId, action: 'android.kme_configuration_shown', target: { type: 'android_enrollment_token', id: row.id },
        details: { tokenId: row.id, requiresApproval: row.requires_approval },
      }, auditCtx);
      return {
        tokenId: row.id, profileType: 'android_enterprise', dpcPackage: ANDROID_DPC_PACKAGE, customJson,
        expiresAt: new Date(row.expires_at).toISOString(), requiresApproval: row.requires_approval,
        warnings: [LONG_TOKEN_WARNINGS.kmeBeforeZeroTouch, ...(row.requires_approval ? [] : [LONG_TOKEN_WARNINGS.noApproval])],
      };
    } finally {
      value.fill(0);
    }
  }));
}

/** The exact URL of the console page hosting the zero-touch iframe, or null without a public HTTPS origin. */
export function zeroTouchParentUrl(origin: string | null): string | null {
  if (!origin || !/^https:\/\/[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$/.test(origin)) return null;
  return `${origin}${ANDROID_ZERO_TOUCH_PAGE}`;
}

/**
 * POST /api/android/zero-touch/iframe-token (see the head of this file): a web token for the zero-touch screen of
 * the tenant's enterprise and the iframe URL with the extras of the active zero-touch token `tokenId`. Audited
 * android.zero_touch_iframe_opened (the token's id, never its value nor the web token).
 */
export async function createZeroTouchIframe(tenantId: number, userId: number, req: { tokenId: unknown }, auditCtx: AuditWriteContext,
  o: { gateway?: AndroidGateway; origin?: string | null } = {}): Promise<AndroidZeroTouchIframe> {
  const origin = o.origin !== undefined ? o.origin : androidConfig().publicOrigin;
  const parentFrameUrl = zeroTouchParentUrl(origin);
  if (!parentFrameUrl) throw new TokenError(409, 'androidPublicOriginNotHttps', 'the console has no public HTTPS origin');
  const gw = o.gateway ?? androidGateway();
  return asTenant(tenantId, { type: 'user', userId }, async () => {
    // The extras first (read in a transaction of their own, the value kept in memory for the answer only).
    const read = await db.transaction(async (trx) => {
      const e = await readEnterprise(trx);
      if (!e || e.state !== 'linked') throw new TokenError(409, 'androidNotLinked', 'no linked Android enterprise');
      const { row, value } = await longTokenValue(trx, tenantId, req.tokenId, 'zero_touch');
      try {
        return { e, row, extras: androidProvisioningExtras(value.toString('utf8')) };
      } finally {
        value.fill(0);
      }
    });
    // Outside any transaction (G-A1): the features of the zero-touch screen only.
    const features = [...ANDROID_ZERO_TOUCH_FEATURES] as IframeFeature[];
    const { value: webToken } = await gw.createWebToken(read.e, { parentFrameUrl, enabledFeatures: features });
    await db.transaction((trx) => audit.appendInTx(trx, {
      tenantId, action: 'android.zero_touch_iframe_opened', target: { type: 'android_enrollment_token', id: read.row.id },
      details: { tokenId: read.row.id, features, requiresApproval: read.row.requires_approval },
    }, auditCtx));
    return {
      iframeUrl: androidZeroTouchIframeUrl(webToken, read.extras), parentFrameUrl, tokenId: read.row.id, requiresApproval: read.row.requires_approval,
      warnings: [LONG_TOKEN_WARNINGS.zeroTouchUnlink, ...(read.row.requires_approval ? [] : [LONG_TOKEN_WARNINGS.noApproval])],
    };
  });
}
