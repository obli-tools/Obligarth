// Tokens of the managed Google Play iframes (android-amapi §9.6, §12.3, AN21, AN22; lot AN-E1): enterprises.webTokens
// for the tenant's enterprise, one screen at a time.
//   - the features come from the screen (closed list, ANDROID_IFRAME_SCREENS), never from the client, never empty:
//     Google opens every feature for a token without features, the zero-touch iframe included (lot AN-F2);
//   - parentFrameUrl is the console's public HTTPS origin (ANDROID_PUBLIC_ORIGIN) followed by one of the pages allowed
//     to host that screen (ANDROID_IFRAME_PAGES): the client names a path, never an origin; Google lets the iframe
//     render only inside that exact URL;
//   - the managed configurations screen is opened for an app of the tenant's own catalog (play or private; never a
//     web app, never an OEMConfig app of another tenant);
//   - the token is answered once, in the body only (Cache-Control no-store): never stored, never logged, never in
//     an audit entry nor a job payload; the audit entry names the screen, its features and the page.
// The console (lot AN-C2) asks for a token when it opens the iframe; the route of this module is not mounted
// (junction AN-A2/AN-P, capability mdm.apps.manage).
import { androidIframeUrl, type AndroidIframeScreen } from '@obligarth/shared/dist/android/apps.js';
import { audit } from '../../audit';
import type { AuditWriteContext } from '../../audit/types';
import { db } from '../../db';
import { asTenant } from '../../db/context';
import { androidConfig } from '../config';
import { readEnterprise } from '../enterprises/registry';
import { androidGateway } from '../gateway';
import type { AndroidGateway, IframeFeature } from '../gateway/types';
import { AndroidAppError, readAndroidApp } from './catalog';
import { featuresOfScreen, parentFrameUrlOf } from './iframes';

export interface IframeTokenRequest {
  screen: string;
  /** Path of the console page hosting the iframe ('/apps/android', '/apps/android/<uuid>/managed-config'). */
  parentPath: string;
  /** managed_config: the app of the catalog (uuid). */
  appId?: string;
  /** Locale of the iframe (the user's language). */
  locale?: string;
}

export interface IframeToken {
  screen: AndroidIframeScreen;
  features: IframeFeature[];
  /** The URL the console loads in the iframe (carries the token). */
  iframeUrl: string;
  parentFrameUrl: string;
}

const LOCALE_RE = /^[a-z]{2,3}(-[A-Za-z0-9]{2,8})?$/;

export { featuresOfScreen, parentFrameUrlOf };

/** Creates a token for one iframe of the tenant's console (see the head of this file). */
export async function createIframeToken(tenantId: number, userId: number, req: IframeTokenRequest, auditCtx: AuditWriteContext,
  o: { gateway?: AndroidGateway; origin?: string | null } = {}): Promise<IframeToken> {
  const features = featuresOfScreen(req.screen);
  if (!features || features.length === 0) throw new AndroidAppError(422, 'androidIframeScreenInvalid', 'unknown iframe screen');
  const screen = req.screen as AndroidIframeScreen;
  const origin = o.origin !== undefined ? o.origin : androidConfig().publicOrigin;
  if (!origin || !origin.startsWith('https://')) throw new AndroidAppError(409, 'androidPublicOriginNotHttps', 'the console has no public HTTPS origin');
  const parentFrameUrl = parentFrameUrlOf(origin, screen, req.parentPath);
  if (!parentFrameUrl) throw new AndroidAppError(422, 'androidIframeParentInvalid', 'this page may not host this iframe');
  const locale = typeof req.locale === 'string' && LOCALE_RE.test(req.locale) ? req.locale : undefined;
  const gw = o.gateway ?? androidGateway();
  return asTenant(tenantId, { type: 'user', userId }, async () => {
    const e = await readEnterprise();
    if (!e || e.state !== 'linked') throw new AndroidAppError(409, 'androidNotLinked', 'no linked Android enterprise');
    let packageName: string | undefined;
    let appId: number | null = null;
    if (screen === 'managed_config') {
      const app = typeof req.appId === 'string' ? await readAndroidApp(db, tenantId, req.appId) : null;
      if (!app) throw new AndroidAppError(404, 'notFound', 'app not found');
      if (app.kind === 'web') throw new AndroidAppError(422, 'androidAppNoManagedConfiguration', 'a web app has no managed configuration');
      // The page must be the app's own (or a policy's): the uuid in an app page is the app's.
      if (req.parentPath.startsWith('/apps/android/') && req.parentPath !== `/apps/android/${app.uuid}/managed-config`) {
        throw new AndroidAppError(422, 'androidIframeParentInvalid', 'this page may not host this iframe');
      }
      packageName = app.identifier;
      appId = Number(app.id);
    }
    const { value } = await gw.createWebToken(e, { parentFrameUrl, enabledFeatures: features });
    await db.transaction((trx) => audit.appendInTx(trx, {
      tenantId, action: 'android.web_token_created', target: { type: 'android_enterprise', id: String(e.id) },
      details: { screen, features, parentPath: req.parentPath, ...(appId !== null ? { appId } : {}) },
    }, auditCtx));
    return { screen, features, parentFrameUrl, iframeUrl: androidIframeUrl(screen, value, { locale, packageName }) };
  });
}
